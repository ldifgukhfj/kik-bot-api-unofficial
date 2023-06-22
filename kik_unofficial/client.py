import asyncio
import logging
import time
from threading import Thread, Event
from typing import Union, List, Tuple
from asyncio import Transport, Protocol
from bs4 import BeautifulSoup

import kik_unofficial.callbacks as callbacks
import kik_unofficial.datatypes.exceptions as exceptions
import kik_unofficial.datatypes.xmpp.chatting as chatting
import kik_unofficial.datatypes.xmpp.group_adminship as group_adminship
import kik_unofficial.datatypes.xmpp.login as login
import kik_unofficial.datatypes.xmpp.roster as roster
import kik_unofficial.datatypes.xmpp.sign_up as sign_up
import kik_unofficial.xmlns_handlers as xmlns_handlers
from colorama import Style, Fore
from kik_unofficial.datatypes.xmpp.auth_stanza import AuthStanza
from kik_unofficial.datatypes.xmpp import account, xiphias
from kik_unofficial.utilities.threading_utils import run_in_new_thread
from kik_unofficial.datatypes.xmpp.base_elements import XMPPElement
from kik_unofficial.http import profile_pictures, content
from kik_unofficial.utilities.cryptographic_utilities import CryptographicUtils

HOST, PORT = CryptographicUtils.get_kik_host_name(), 5223
log = logging.getLogger('kik_unofficial')
log.setLevel("INFO")
show_full_chat_message = 0


class KikClient:
    """
    The main kik class with which you're managing a kik connection and sending commands
    """

    def __init__(self, callback: callbacks.KikClientCallback, kik_username, kik_password,
                 kik_node=None, device_id_override=None, android_id_override=None, operator_override=None,
                 brand_override=None, model_override=None, android_sdk_override=None,
                 install_date_override=None, logins_since_install_override=None,
                 registrations_since_install_override=None, disable_rsa_cert=False):
        """
        Initializes a connection to Kik servers.
        If you want to automatically login too, use the username and password parameters.

        :param callback: a callback instance containing your callbacks implementation.
                         This way you'll get notified whenever certain event happen.
                         Look at the KikClientCallback class for more details
        :param kik_username: the kik username or email to log in with.
        :param kik_password: the kik password to log in with.
        :param kik_node: the username plus 3 letters after the "_" and before the "@" in the JID. If you know it,
                         authentication will happen faster and without a login. otherwise supply None.
        """
        self.username = kik_username
        self.password = kik_password
        self.kik_node = kik_node
        self.kik_email = None
        self.disable_rsa_cert = disable_rsa_cert
        self.device_id_override = device_id_override
        self.android_id_override = android_id_override
        self.operator_override = operator_override
        self.brand_override = brand_override
        self.model_override = model_override
        self.android_sdk_override = android_sdk_override
        self.install_date_override = install_date_override
        self.logins_since_install_override = logins_since_install_override
        self.registrations_since_install_override = registrations_since_install_override
        self.debug = f'[' + Style.BRIGHT + Fore.MAGENTA + '^' + Style.RESET_ALL + '] '
        self.info = f'[' + Style.BRIGHT + Fore.GREEN + '+' + Style.RESET_ALL + '] '
        self.warning = f'[' + Style.BRIGHT + Fore.YELLOW + '!' + Style.RESET_ALL + '] '
        self.critical = f'[' + Style.BRIGHT + Fore.RED + 'X' + Style.RESET_ALL + '] '

        self.callback = callback
        self.authenticator = AuthStanza(self)

        self.connected = False
        self.authenticated = False
        self.connection = None
        self.is_expecting_connection_reset = False
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)

        self._known_users_information = set()
        self._new_user_added_event = Event()

        self.should_login_on_connection = kik_username is not None and kik_password is not None
        self.force_login_attempt = False
        self._connect()

    def _connect(self):
        """
        Runs the kik connection thread, which creates an encrypted (SSL based) TCP connection
        to the kik servers.
        """
        self.kik_connection_thread = Thread(target=self._kik_connection_thread_function, name="Kik Connection")
        self.kik_connection_thread.start()
        # self.kik_connection_thread.join()

    def _on_connection_made(self):
        """
        Gets called when the TCP connection to kik's servers is done and we are connected.
        Now we might initiate a login request or an auth request.
        """
        if self._can_skip_login():
            # we have all required credentials, we can authenticate
            log.info(self.info + f'Establishing authenticated connection using kik node \'{self.kik_node}\'...')

            message = login.EstablishAuthenticatedSessionRequest(self.kik_node, self.username, self.password,
                                                                 self.device_id_override)
            self.initial_connection_payload = message.serialize()
        else:
            message = login.MakeAnonymousStreamInitTag(self.device_id_override, n=1)
            self.initial_connection_payload = message.serialize()

        self.connection.send_raw_data(self.initial_connection_payload)

    def _can_skip_login(self) -> bool:
        if self.force_login_attempt:
            self.force_login_attempt = False
            return False
        else:
            return self.username is not None and self.password is not None and self.kik_node is not None

    def _establish_authenticated_session(self, kik_node):
        """
        Updates the kik node and creates a new connection to kik servers.
        This new connection will be initiated with another payload which proves
        we have the credentials for a specific user. This is how authentication is done.

        :param kik_node: The user's kik node (everything before '@' in JID).
        """
        self.kik_node = kik_node
        log.info(self.info + f"Closing current connection and creating a new authenticated one.")

        self.disconnect()
        self._connect()

    def login(self, username, password, captcha_result=None):
        """
        Sends a login request with the given kik username and password

        :param username: Your kik username or email
        :param password: Your kik password
        :param captcha_result: If this parameter is provided, it is the answer to the captcha given in the previous
        login attempt.
        """
        self.username = username
        self.password = password
        login_request = login.LoginRequest(username, password, captcha_result, self.device_id_override,
                                           self.android_id_override,
                                           self.operator_override, self.brand_override, self.model_override,
                                           self.android_sdk_override,
                                           self.install_date_override, self.logins_since_install_override,
                                           self.registrations_since_install_override)
        login_type = "email" if '@' in self.username else "username"
        log.info(
            self.info + f'Logging in with {login_type} \'{username}\' and a given password {"*" * len(password)}...')
        return self._send_xmpp_element(login_request)

    def register(self, email, username, password, first_name, last_name, birthday="1974-11-20", captcha_result=None):
        """
        Sends a register request to sign up a new user to kik with the given details.
        """
        self.username = username
        self.password = password
        register_message = sign_up.RegisterRequest(email, username, password, first_name, last_name, birthday,
                                                   captcha_result,
                                                   self.device_id_override, self.android_id_override)
        log.info(self.info + f'Sending sign up request (name: {first_name} {last_name}, email: {email})...')
        return self._send_xmpp_element(register_message)

    def request_roster(self, is_big=True, timestamp=None):
        """
        Requests the list of chat partners (people and groups). This is called roster in XMPP terms.
        """
        log.info(self.info + f'Requesting roster (list of chat partners)...')
        return self._send_xmpp_element(roster.FetchRosterRequest(is_big=is_big, timestamp=timestamp))

    # -------------------------------
    # Common Messaging Operations
    # -------------------------------

    def send_chat_message(self, peer_jid: str, message: str, bot_mention_jid=None):
        """
        Sends a text chat message to another person or a group with the given JID/username.

        :param peer_jid: The Jabber ID for which to send the message (looks like username_ejs@talk.kik.com)
                         If you don't know the JID of someone, you can also specify a kik username here.
        :param message: The actual message body
        :param bot_mention_jid: If an official bot is referenced, their jid must be embedded as mention for them
        to respond.
        """
        peer_jid = self.get_jid(peer_jid)

        if self.is_group_jid(peer_jid):
            if show_full_chat_message > 0:
                log.info(self.info + f'Sending chat message \'{message}\' to group \'{peer_jid}\'')
            else:
                log.info(self.info + f'Sending chat message \'{message[:10]}\' to group \'{peer_jid}\'')
            return self._send_xmpp_element(chatting.OutgoingGroupChatMessage(peer_jid, message, bot_mention_jid))
        else:
            if show_full_chat_message > 0:
                log.info(self.info + f'Sending chat message \'{message}\' to user \'{peer_jid}\'')
            else:
                log.info(self.info + f'Sending chat message \'{message[:10]}\' to user \'{peer_jid}\'')
            return self._send_xmpp_element(chatting.OutgoingChatMessage(peer_jid, message, False, bot_mention_jid))

    def send_chat_image(self, peer_jid: str, image_file, allow_forward=False, allow_save=False, fake_camera=False):
        """
        Sends an image chat message to another person or a group with the given JID/username.
        :param fake_camera: Send image as if it was live from camera. bool
        :param allow_save: Allow Saving of the image. bool
        :param allow_forward: Allow Forwarding of the Image. bool

        :param peer_jid: The Jabber ID for which to send the message (looks like username_ejs@talk.kik.com)
                         If you don't know the JID of someone, you can also specify a kik username here.
        :param image_file: The path to the image file OR its bytes OR an IOBase object to send.
        """

        peer_jid = self.get_jid(peer_jid)
        is_group = self.is_group_jid(peer_jid)

        log.info(self.info + f'Sending chat image to {"group" if is_group else "user"} \'{peer_jid}\'')

        image_request = chatting.OutgoingChatImage(peer_jid, image_file, allow_forward, allow_save, fake_camera,
                                                   is_group)

        if fake_camera:
            app_id = "com.kik.ext.camera"
        else:
            app_id = "com.kik.ext.gallery"

        content.upload_gallery_image(self, image_request, app_id, self.kik_node + '@talk.kik.com', self.username,
                                     self.password)
        return image_request.message_id

    def send_chat_video(self, peer_jid: str, video_file, thumbnail_file, video_duration, forward=True, save=True,
                        auto_play=False, muted=False, looping=False):
        """
        Sends an image chat message to another person or a group with the given JID/username.
        WARNING: videos above 15 MB (15728640 bytes) will be rejected by Kik's upload server.

        :param video_duration: The length of the video in milliseconds
        :param forward: Allow forwarding of the video. bool
        :param save: Allow saving of the video. bool
        :param auto_play: Causes the video to auto-play when it is on the screen. bool
        :param muted: Mutes the video when played. bool
        :param looping: Loops the video when played. bool
        :param peer_jid: The Jabber ID for which to send the message (looks like username_ejs@talk.kik.com)
                         If you don't know the JID of someone, you can also specify a kik username here.
        :param video_file: The path to the video file OR its bytes OR an IOBase object to send.
        :param thumbnail_file: The path to the image file OR its bytes OR an IOBase object to send.
        """
        peer_jid = self.get_jid(peer_jid)
        is_group = self.is_group_jid(peer_jid)

        log.info(self.info + f' Sending chat video to {"group" if is_group else "user"} \'{peer_jid}\'')

        video_request = chatting.OutgoingChatVideo(peer_jid, video_file, thumbnail_file, video_duration, forward, save,
                                                   auto_play, muted, looping, is_group)

        # Do not send the video stanza until the video is successfully uploaded to the Kik platform server
        # This prevents "failed to load" errors
        content.upload_gallery_video(self, video_request, "com.kik.ext.video-gallery", self.kik_node + '@talk.kik.com',
                                     self.username, self.password)

        return video_request.message_id

    def send_read_receipt(self, peer_jid: str, receipt_message_id: str, group_jid=None):
        """
        Sends a read receipt for a previously sent message, to a specific user or group.

        :param peer_jid: The JID of the user to which to send the receipt.
        :param receipt_message_id: The message ID that the receipt is sent for
        :param group_jid If the receipt is sent for a message that was sent in a group,
                         this parameter should contain the group's JID
        """
        log.info(self.info + f'Sending read receipt to JID {peer_jid} for message ID {receipt_message_id}')
        return self._send_xmpp_element(chatting.OutgoingReadReceipt(peer_jid, receipt_message_id, group_jid))

    def send_delivered_receipt(self, peer_jid: str, receipt_message_id: str, group_jid: str = None):
        """
        Sends a receipt indicating that a specific message was received, to another person.

        :param peer_jid: The other peer's JID to send to receipt to
        :param receipt_message_id: The message ID for which to generate the receipt
        :param group_jid: The group's JID, in case the receipt is sent in a group (None otherwise)
        """
        log.info(self.info + f'Sending delivered receipt to JID {peer_jid} for message ID {receipt_message_id}')
        return self._send_xmpp_element(chatting.OutgoingDeliveredReceipt(peer_jid, receipt_message_id, group_jid))

    def send_is_typing(self, peer_jid: str, is_typing: bool):
        """
        Updates the 'is typing' status of the bot during a conversation.

        :param peer_jid: The JID that the notification will be sent to
        :param is_typing: If true, indicates that we're currently typing, or False otherwise.
        """
        if self.is_group_jid(peer_jid):
            return self._send_xmpp_element(chatting.OutgoingGroupIsTypingEvent(peer_jid, is_typing))
        else:
            return self._send_xmpp_element(chatting.OutgoingIsTypingEvent(peer_jid, is_typing))

    def send_gif_image_sub(self, peer_jid: str, gif_path):
        """
        Sends a GIF image to another person or a group with the given JID/username.
        The GIF is is store in .json by user when setting as a trigger.
        :param peer_jid: The Jabber ID for which to send the message (looks like username_ejs@talk.kik.com
        :param gif_path: The path to the file that contains gif information
        """
        if self.is_group_jid(peer_jid):
            log.info(self.info + f'Sending a GIF message to group \'{peer_jid}\'...')
            return self._send_xmpp_element(chatting.OutgoingGIFMessageSub(peer_jid, gif_path, True))
        else:
            log.info(self.info + f'Sending a GIF message to user \'{peer_jid}\'...')
            return self._send_xmpp_element(chatting.OutgoingGIFMessageSub(peer_jid, gif_path, False))

    def send_custom_gif_image(self, peer_jid: str, path, url):
        """
        Sends a GIF image to another person or a group with the given JID/username.
        The GIF is taken from tendor.com, based on search keywords.
        :param url: Url for the GIF image
        :param path: File Path to GIF image
        :param peer_jid: The Jabber ID for which to send the message (looks like username_ejs@talk.kik.com
        """
        if self.is_group_jid(peer_jid):
            log.info(self.info + f'Sending a GIF message to group \'{peer_jid}\'...')
            return self._send_xmpp_element(chatting.OutgoingCustomGIFMessage(peer_jid, path, url, True))
        else:
            log.info(self.info + f'Sending a GIF message to user \'{peer_jid}\'...')
            return self._send_xmpp_element(chatting.OutgoingCustomGIFMessage(peer_jid, path, url, False))

    def send_gif_image(self, peer_jid: str, search_term):
        """
        Sends a GIF image to another person or a group with the given JID/username.
        The GIF is taken from tendor.com, based on search keywords.
        :param peer_jid: The Jabber ID for which to send the message (looks like username_ejs@talk.kik.com
        :param search_term: The search term to use when searching GIF images on tendor.com
        """
        if self.is_group_jid(peer_jid):
            log.info(self.info + f'Sending a GIF message to group \'{peer_jid}\'...')
            return self._send_xmpp_element(chatting.OutgoingGIFMessage(peer_jid, search_term, True))
        else:
            log.info(self.info + f'Sending a GIF message to user \'{peer_jid}\'...')
            return self._send_xmpp_element(chatting.OutgoingGIFMessage(peer_jid, search_term, False))

    def request_info_of_users(self, peer_jids: Union[str, List[str]]):
        """
        Requests basic information (username, JID, display name, picture) of some users.
        When the information arrives, the callback on_peer_info_received() will fire.

        :param peer_jids: The JID(s) or the username(s) for which to request the information.
                          If you want to request information for more than one user, supply a list of strings.
                          Otherwise, supply a string
        """

        return self._send_xmpp_element(roster.QueryUsersInfoRequest(peer_jids))

    def add_friend(self, peer_jid):
        return self._send_xmpp_element(roster.AddFriendRequest(peer_jid))

    def remove_friend(self, peer_jid):
        return self._send_xmpp_element(roster.RemoveFriendRequest(peer_jid))

    def send_link(self, peer_jid, link, title, text='', app_name='Webpage', preview=False):
        return self._send_xmpp_element(chatting.OutgoingLinkShareEvent(peer_jid, link, title, text, app_name, preview))

    def xiphias_get_users(self, peer_jids: Union[str, List[str]]):
        """
        Calls the new format xiphias message to request user data such as profile creation date
        and background picture URL.

        :param peer_jids: one jid, or a list of jids
        """
        return self._send_xmpp_element(xiphias.UsersRequest(peer_jids))

    def xiphias_get_users_by_alias(self, alias_jids: Union[str, List[str]]):
        """
        Like xiphias_get_users, but for aliases instead of jids.

        :param alias_jids: one jid, or a list of jids
        """
        return self._send_xmpp_element(xiphias.UsersByAliasRequest(alias_jids))

    # --------------------------
    #  Group Admin Operations
    # -------------------------

    def change_group_name(self, group_jid: str, new_name: str):
        """
        Changes the a group's name to something new

        :param group_jid: The JID of the group whose name should be changed
        :param new_name: The new name to give to the group
        """
        log.info(self.info + f'Requesting a group name change for JID {group_jid} to \'{new_name}\'')
        return self._send_xmpp_element(group_adminship.ChangeGroupNameRequest(group_jid, new_name))

    def add_peer_to_group(self, group_jid, peer_jid):
        """
        Adds someone to a group

        :param group_jid: The JID of the group into which to add a user
        :param peer_jid: The JID of the user to add
        """
        log.info(self.info + f'Requesting to add user {peer_jid} into the group {group_jid}')
        return self._send_xmpp_element(group_adminship.AddToGroupRequest(group_jid, peer_jid))

    def remove_peer_from_group(self, group_jid, peer_jid):
        """
        Kicks someone out of a group

        :param group_jid: The group JID from which to remove the user
        :param peer_jid: The JID of the user to remove
        """
        log.info(self.info + f'Requesting removal of user {peer_jid} from group {group_jid}')
        return self._send_xmpp_element(group_adminship.RemoveFromGroupRequest(group_jid, peer_jid))

    def ban_member_from_group(self, group_jid, peer_jid):
        """
        Bans a member from the group

        :param group_jid: The JID of the relevant group
        :param peer_jid: The JID of the user to ban
        """
        log.info(self.info + f'Requesting ban of user {peer_jid} from group {group_jid}')
        return self._send_xmpp_element(group_adminship.BanMemberRequest(group_jid, peer_jid))

    def unban_member_from_group(self, group_jid, peer_jid):
        """
        Undos a ban of someone from a group

        :param group_jid: The JID of the relevant group
        :param peer_jid: The JID of the user to un-ban from the gorup
        """
        log.info(self.info + f'Requesting un-banning of user {peer_jid} from the group {group_jid}')
        return self._send_xmpp_element(group_adminship.UnbanRequest(group_jid, peer_jid))

    def join_group_with_token(self, group_hashtag, group_jid, join_token):
        """
        Tries to join into a specific group, using a cryptographic token that was received earlier from a search

        :param group_hashtag: The public hashtag of the group into which to join (like '#Music')
        :param group_jid: The JID of the same group
        :param join_token: a token that can be extracted in the callback on_group_search_response, after calling
                           search_group()
        """
        log.info(self.info + f'Trying to join the group \'{group_hashtag}\' with JID {group_jid}')
        return self._send_xmpp_element(roster.GroupJoinRequest(group_hashtag, join_token, group_jid))

    def leave_group(self, group_jid):
        """
        Leaves a specific group

        :param group_jid: The JID of the group to leave
        """
        log.info(self.info + f'Leaving group {group_jid}')
        return self._send_xmpp_element(group_adminship.LeaveGroupRequest(group_jid))

    def promote_to_admin(self, group_jid, peer_jid):
        """
        Turns some group member into an admin

        :param group_jid: The group JID for which the member will become an admin
        :param peer_jid: The JID of user to turn into an admin
        """
        log.info(self.info + f'Promoting user {peer_jid} to admin in group {group_jid}')
        return self._send_xmpp_element(group_adminship.PromoteToAdminRequest(group_jid, peer_jid))

    def demote_admin(self, group_jid, peer_jid):
        """
        Turns an admin of a group into a regular user with no amidships capabilities.

        :param group_jid: The group JID in which the rights apply
        :param peer_jid: The admin user to demote
        :return:
        """
        log.info(self.info + f'Demoting user {peer_jid} to a regular member in group {group_jid}')
        return self._send_xmpp_element(group_adminship.DemoteAdminRequest(group_jid, peer_jid))

    def add_members(self, group_jid, peer_jids: Union[str, List[str]]):
        """
        Adds multiple users to a specific group at once

        :param group_jid: The group into which to join the users
        :param peer_jids: a list (or a single string) of JIDs to add to the group
        """
        log.info(self.info + f'Adding some members to the group {group_jid}')
        return self._send_xmpp_element(group_adminship.AddMembersRequest(group_jid, peer_jids))

    # ----------------------
    # Other Operations
    # ----------------------

    def search_group(self, search_query):
        """
        Searches for public groups using a query
        Results will be returned using the on_group_search_response() callback

        :param search_query: The query that contains some of the desired groups' name.
        """
        log.info(self.info + f'Initiating a search for groups using the query \'{search_query}\'')
        return self._send_xmpp_element(roster.GroupSearchRequest(search_query))

    def check_username_uniqueness(self, username, silent=False):
        """
        Checks if the given username is available for registration.
        Results are returned in the on_username_uniqueness_received() callback

        :param silent: Quiets log, for usage as a bot ping.
        :param username: The username to check for its existence
        """
        if not silent:
            log.info(self.info + f'Checking for Uniqueness of username \'{username}\'')
        return self._send_xmpp_element(sign_up.CheckUsernameUniquenessRequest(username))

    def set_profile_picture(self, filename):
        """
        Sets the profile picture of the current user

        :param filename: The path to the file OR its bytes OR an IOBase object to set
        """
        log.info(self.info + f'Setting the profile picture to file \'{filename}\'')
        profile_pictures.set_profile_picture(filename, self.kik_node + '@talk.kik.com', self.username, self.password)

    def set_background_picture(self, filename):
        """
        Sets the background picture of the current user

        :param filename: The path to the image file OR its bytes OR an IOBase object to set
        """
        log.info(self.info + f'Setting the background picture to filename \'{filename}\'')
        profile_pictures.set_background_picture(filename, self.kik_node + '@talk.kik.com', self.username, self.password)

    def send_captcha_result(self, stc_id, captcha_result):
        """
        In case a captcha was encountered, solves it using an element ID and a response parameter.
        The stc_id can be extracted from a CaptchaElement, and the captcha result needs to be extracted manually with
        a browser. Please see solve_captcha_wizard() for the steps needed to solve the captcha

        :param stc_id: The stc_id from the CaptchaElement that was encountered
        :param captcha_result: The answer to the captcha (which was generated after solved by a human)
        """
        log.info(self.info + f'Trying to solve a captcha with result: \'{captcha_result}\'')
        return self._send_xmpp_element(login.CaptchaSolveRequest(stc_id, captcha_result))

    def change_display_name(self, first_name, last_name):
        """
        Changes the display name

        :param first_name: The first name
        :param last_name: The last name
        """
        log.info(self.info + f'Changing the display name to \'{first_name} {last_name}\'')
        return self._send_xmpp_element(account.ChangeNameRequest(first_name, last_name))

    def change_password(self, new_password, email):
        """
        Changes the login password

        :param new_password: The new login password to set for the account
        :param email: The current email of the account
        """
        log.info(self.info + f'Changing the password of the account')
        return self._send_xmpp_element(account.ChangePasswordRequest(self.password, new_password, email, self.username))

    def change_email(self, old_email, new_email):
        """
        Changes the email of the current account

        :param old_email: The current email
        :param new_email: The new email to set
        """
        log.info(self.info + f'Changing account email to \'{new_email}\'')
        return self._send_xmpp_element(account.ChangeEmailRequest(self.password, old_email, new_email))

    def disconnect(self):
        """
        Closes the connection to kik's servers.
        """
        log.info(self.critical + "Disconnecting.")
        self.connection.close()
        self.is_expecting_connection_reset = True

        # self.loop.call_soon(self.loop.stop)

    # -----------------
    # Internal methods
    # -----------------

    def _send_xmpp_element(self, message: XMPPElement):
        """
        Serializes and sends the given XMPP element to kik servers
        :param xmpp_element: The XMPP element to send
        :return: The UUID of the element that was sent
        """
        while not self.connected:
            log.debug(self.warning + f'Waiting for connection.')
            time.sleep(0.1)
        if type(message.serialize()) is list:
            log.debug(self.warning + f'Sending multi packet data.')
            packets = message.serialize()
            for p in packets:
                self.loop.call_soon_threadsafe(self.connection.send_raw_data, p)
            return message.message_id
        else:
            self.loop.call_soon_threadsafe(self.connection.send_raw_data, message.serialize())
            return message.message_id

    def send_stanza(self, raw_xmpp: str or bytes or list[bytes], stanza_type=False):
        log.debug(self.debug + f'Sending {stanza_type if stanza_type else "Generic"} Stanza')
        return self._send_xmpp_element(chatting.OutgoingStanza(raw_xmpp))

    @run_in_new_thread
    def _on_new_data_received(self, data: bytes):
        """
        Gets called whenever we get a whole new XML element from kik's servers.
        :param data: The data received (bytes)
        """

        if data == b' ':
            # Happens every half hour. Disconnect after 10th time. Some kind of keep-alive? Let's send it back.
            self.loop.call_soon_threadsafe(self.connection.send_raw_data, b' ')
            return

        xml_element = BeautifulSoup(data.decode('utf-8'), features='xml')
        xml_element = next(iter(xml_element)) if len(xml_element) > 0 else xml_element

        # choose the handler based on the XML tag name

        if xml_element.name == "k":
            self._handle_received_k_element(xml_element)
        elif xml_element.name == "iq":
            self._handle_received_iq_element(xml_element)
        elif xml_element.name == "message":
            self._handle_xmpp_message(xml_element)
        elif xml_element.name == 'stc':
            if xml_element.stp['type'] == 'ca':
                self.callback.on_captcha_received(login.CaptchaElement(xml_element))
            elif xml_element.stp['type'] == 'bn':
                self.callback.on_temp_ban_received(login.TempBanElement(xml_element))
            else:
                log.error(self.critical + f'Unknown stc element type: {xml_element["type"]}')
        elif xml_element.name == 'ack':
            pass
        else:
            log.error(self.critical + f'Unknown element type: {xml_element.name}')

    def _handle_received_k_element(self, k_element: BeautifulSoup):
        """
        The 'k' element appears to be kik's connection-related stanza.
        It lets us know if a connection or a login was successful or not.

        :param k_element: The XML element we just received from kik.
        """
        if k_element['ok'] == "1":
            self.connected = True

            if 'ts' in k_element.attrs:
                # authenticated!
                log.info(self.info + f'Authenticated successfully.')
                self.authenticated = True
                if not self.disable_rsa_cert:
                    self.authenticator.send_stanza()
                self.callback.on_authenticated()
            elif self.should_login_on_connection:
                self.login(self.username, self.password)
                self.should_login_on_connection = False
        else:
            # k failed, and the connection is closed.
            # this usually will contain a "noauth" or a "wait" child element
            conn_failed = login.ConnectionFailedResponse(k_element)
            if self.kik_node is not None:
                log.info(self.critical + f" Authentication failed {conn_failed.message}, trying to log in...")
                self.force_login_attempt = True
                self.loop.call_soon_threadsafe(self._connect)
            else:
                self.callback.on_connection_failed(conn_failed)

    def _handle_received_iq_element(self, iq_element: BeautifulSoup):
        """
        The 'iq' (info/query) stanzas in XMPP represents the request/ response elements.
        We send an iq stanza to request for information, and we receive an iq stanza in response to this request,
        with the same ID attached to it.
        For a great explanation of this stanza: http://slixmpp.readthedocs.io/api/stanza/iq.html

        :param iq_element: The iq XML element we just received from kik.
        """
        '''<iq id="5e48590a-c539-47d2-aaa7-29859a9ac0bd" to="lucky_bot_16_6gp@talk.kik.com/CAN38cb924557946f31c341c6ec37d31f71" type="error">
           <error code = "503" type="cancel">
           <service-unavailable xmlns="urn:ietf:params:xml:ns:xmpp-stanzas"/>
           </error>
           </iq>'''
        if iq_element.error:
            if "bad-request" in dir(iq_element.error):
                raise Exception(self.critical + f'Received a Bad Request error for stanza with ID {iq_element.attrs["id"]}')
            if iq_element.error.find("service-unavailable"):
                xmlns_handlers.PeersInfoErrorHandler(self.callback, self).handle(iq_element)
                return

        query = iq_element.query
        if hasattr(query, "attrs"):
            xml_namespace = query['xmlns'] if 'xmlns' in query.attrs else query['xmlns:']
        else:
            if query:
                if "xmlns:" in query:
                    xml_namespace = query['xmlns:']
                else:
                    log.info(self.critical + f"IQ Element has no xml namespace: {iq_element}")
                    return
            else:
                log.info(self.critical + f"IQ Element is none {iq_element}")
                return
        self._handle_response(xml_namespace, iq_element)

    def _handle_response(self, xmlns, iq_element):
        """
        Handles a response that we receive from kik after our initiated request.
        Examples: response to a group search, response to fetching roster, etc.

        :param xmlns: The XML namespace that helps us understand what type of response this is
        :param iq_element: The actual XML element that contains the response
        """
        if xmlns == 'kik:iq:check-unique':
            xmlns_handlers.CheckUsernameUniqueResponseHandler(self.callback, self).handle(iq_element)
        elif xmlns == 'jabber:iq:register':
            xmlns_handlers.RegisterOrLoginResponseHandler(self.callback, self).handle(iq_element)
        elif xmlns == 'jabber:iq:roster':
            xmlns_handlers.RosterResponseHandler(self.callback, self).handle(iq_element)
        elif xmlns == 'kik:iq:friend' or xmlns == 'kik:iq:friend:batch':
            xmlns_handlers.PeersInfoResponseHandler(self.callback, self).handle(iq_element)
        elif xmlns == 'kik:iq:xiphias:bridge':
            xmlns_handlers.XiphiasHandler(self.callback, self).handle(iq_element)
        elif xmlns == 'kik:auth:cert':
            self.authenticator.handle(iq_element)
        elif xmlns == 'kik:iq:QoS':
            xmlns_handlers.HistoryHandler(self.callback, self).handle(iq_element)
        elif xmlns == 'kik:iq:user-profile':
            xmlns_handlers.UserProfileHandler(self.callback, self).handle(iq_element)

    def _handle_xmpp_message(self, xmpp_message: BeautifulSoup):
        """
        an XMPP 'message' in the case of Kik is the actual stanza we receive when someone sends us a message
        (weather groupchat or not), starts typing, stops typing, reads our message, etc.
        Examples: http://slixmpp.readthedocs.io/api/stanza/message.html

        :param xmpp_message: The XMPP 'message' element we received
        """
        self._handle_kik_event(xmpp_message)

    def _handle_kik_event(self, xmpp_element):
        """
        Handles kik "push" events, like a new message that arrives.

        :param xmpp_element: The XML element that we received with the information about the event
        """
        if "xmlns" in xmpp_element.attrs:
            # The XML namespace is different for iOS and Android, handle the messages with their actual type
            if xmpp_element['type'] == "chat":
                xmlns_handlers.XMPPMessageHandler(self.callback, self).handle(xmpp_element)
            elif xmpp_element['type'] == "groupchat":
                xmlns_handlers.GroupXMPPMessageHandler(self.callback, self).handle(xmpp_element)
            elif xmpp_element['type'] == "receipt":
                if xmpp_element.g:
                    self.callback.on_group_receipts_received(chatting.IncomingGroupReceiptsEvent(xmpp_element))
                else:
                    xmlns_handlers.XMPPMessageHandler(self.callback, self).handle(xmpp_element)
            elif xmpp_element['type'] == "is-typing":
                # some clients send is-typing this way?
                xmlns_handlers.XMPPMessageHandler(self.callback, self).handle(xmpp_element)
            elif xmpp_element['type'] == "error":
                # error type happens on KIK jail (Restricted Group Access)
                pass
            else:
                log.error(self.critical + f'Unknown XMPP element type: {xmpp_element}')
        else:
            # iPads send messages without xmlns, try to handle it as jabber:client
            xmlns_handlers.XMPPMessageHandler(self.callback, self).handle(xmpp_element)

    def _on_connection_lost(self):
        """
        Gets called when the connection to kik's servers is (unexpectedly) lost.
        It could be that we received a connection reset packet for example.
        :return:
        """
        self.connected = False
        if not self.is_expecting_connection_reset:
            log.info(self.critical + f'The connection was unexpectedly lost')

        self.is_expecting_connection_reset = False

    def _kik_connection_thread_function(self):
        """
        The Kik Connection thread main function.
        Initiates the asyncio loop and actually connects.
        """
        # If there is already a connection going, than wait for it to stop
        if self.loop and self.loop.is_running():
            self.loop.call_soon_threadsafe(self.connection.close)
            log.debug(self.warning + "Waiting for the previous connection to stop.")
            while self.loop.is_running():
                log.debug(self.warning + "Still Waiting for the previous connection to stop.")
                time.sleep(1)

        log.info(self.info + "Initiating the Kik Connection thread and connecting to kik server...")

        # create the connection and launch the asyncio loop
        self.connection = KikConnection(self.loop, self)
        connection_coroutine = self.loop.create_connection(lambda: self.connection, HOST, PORT, ssl=True)
        self.loop.run_until_complete(connection_coroutine)

        log.debug(self.warning + "Running main loop")
        self.loop.run_forever()
        log.debug(self.warning + "Main loop ended.")
        self.callback.on_disconnected()

    def get_jid(self, username_or_jid):
        if '@' in username_or_jid:
            # this is already a JID.
            return username_or_jid
        else:
            username = username_or_jid

            # first search if we already have it
            if self.get_jid_from_cache(username) is None:
                # go request for it

                self._new_user_added_event.clear()
                self.request_info_of_users(username)
                if not self._new_user_added_event.wait(5.0):
                    raise TimeoutError(self.critical + f'Could not get the JID for username {username} in time')

            return self.get_jid_from_cache(username)

    def get_jid_from_cache(self, username):
        for user in self._known_users_information:
            if user.username.lower() == username.lower():
                return user.jid

        return None

    @staticmethod
    def log_format():
        return '[%(asctime)-15s] %(levelname)-6s: %(message)s'

    @staticmethod
    def is_group_jid(jid):
        if '@talk.kik.com' in jid:
            return False
        elif '@groups.kik.com' in jid:
            return True
        else:
            raise exceptions.KikApiException('Not a valid jid')


class KikConnection(Protocol):
    def __init__(self, loop, api: KikClient):
        self.debug = f'[' + Style.BRIGHT + Fore.MAGENTA + '^' + Style.RESET_ALL + '] '
        self.info = f'[' + Style.BRIGHT + Fore.GREEN + '+' + Style.RESET_ALL + '] '
        self.warning = f'[' + Style.BRIGHT + Fore.YELLOW + '!' + Style.RESET_ALL + '] '
        self.critical = f'[' + Style.BRIGHT + Fore.RED + 'X' + Style.RESET_ALL + '] '
        self.api = api
        self.loop = loop
        self.partial_data = None  # type: bytes
        self.partial_data_start_tag = None  # type: str
        self.transport = None  # type: Transport

    def connection_made(self, transport: Transport):
        self.transport = transport
        log.info(self.info + "Connected.")
        self.api._on_connection_made()

    def data_received(self, data: bytes):

        log.debug(self.debug + f'Received raw data: {data}')
        if self.partial_data is None:
            if len(data) < 16384 and data.endswith(b'>'):
                self.loop.call_soon_threadsafe(self.api._on_new_data_received, data)
            else:
                log.debug(self.debug + f'Multi-packet data, waiting for next packet.')
                start_tag, is_closing = self.parse_start_tag(data)
                self.partial_data_start_tag = start_tag
                self.partial_data = data
        else:
            if self.ends_with_tag(self.partial_data_start_tag, data):
                self.loop.call_soon_threadsafe(self.api._on_new_data_received, self.partial_data + data)
                self.partial_data = None
                self.partial_data_start_tag = None
            else:
                log.debug(self.debug + f'Waiting for another packet, size={len(self.partial_data)}')
                self.partial_data += data

    @staticmethod
    def parse_start_tag(data: bytes) -> Tuple[bytes, bool]:
        tag = data.lstrip(b'<')
        tag = tag.split(b'>')[0]
        tag = tag.split(b' ')[0]
        is_closing = tag.endswith(b'/')
        if is_closing:
            tag = tag[:-1]
        return tag, is_closing

    @staticmethod
    def ends_with_tag(expected_end_tag: bytes, data: bytes):
        return data.endswith(b'</' + expected_end_tag + b'>')

    def connection_lost(self, exception):
        self.loop.call_soon_threadsafe(self.api._on_connection_lost)
        self.loop.stop()

    def send_raw_data(self, data: bytes):
        log.debug(self.debug + f'Sending raw data: {data}')
        self.transport.write(data)

    def close(self):
        if self.transport:
            self.transport.write(b'</k>')
