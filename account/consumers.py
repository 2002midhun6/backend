import json
import logging
import urllib.parse
import asyncio
from channels.generic.websocket import AsyncWebsocketConsumer
from channels.db import database_sync_to_async
from django.utils import timezone
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from account.models import Job, JobApplication, Conversation, Message, CustomUser
import jwt

logger = logging.getLogger('django')

class ChatConsumer(AsyncWebsocketConsumer):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.heartbeat_task = None
        self.is_connected = False
        
    async def connect(self):
        try:
            self.job_id = self.scope['url_route']['kwargs']['job_id']
            self.room_group_name = f'chat_{self.job_id}'
            
            query_string = self.scope.get('query_string', b'').decode()
            cookies = self.scope.get('cookies', {})
            logger.info(f"WebSocket connect attempt: job_id={self.job_id}")
            
            # Quick authentication check
            self.user = await self.authenticate_user(cookies, query_string)
            
            if not self.user or self.user.is_anonymous:
                logger.error(f"Authentication failed for job_id={self.job_id}")
                await self.close(code=4001)
                return
            
            # Quick authorization check
            is_authorized = await self.is_user_authorized()
            if not is_authorized:
                logger.error(f"Authorization failed: {self.user.email}, job_id={self.job_id}")
                await self.close(code=4003)
                return
            
            # Join room group
            await self.channel_layer.group_add(self.room_group_name, self.channel_name)
            await self.accept()
            self.is_connected = True
            
            # Start heartbeat
            self.heartbeat_task = asyncio.create_task(self.heartbeat_loop())
            
            logger.info(f"WebSocket connected successfully: user={self.user.email}, job_id={self.job_id}")
            
            # Notify others
            await self.channel_layer.group_send(
                self.room_group_name,
                {
                    'type': 'user_joined',
                    'message': {
                        'event': 'user_joined',
                        'user_id': self.user.id,
                        'user_name': self.user.name,
                        'user_role': self.user.role,
                        'timestamp': timezone.now().isoformat()
                    }
                }
            )
            
        except Exception as e:
            logger.error(f"Connect error: {str(e)}")
            await self.close(code=4000)

    async def authenticate_user(self, cookies, query_string):
        """Fast authentication method"""
        try:
            # Try cookie first
            token = cookies.get('access_token')
            if token:
                jwt_auth = JWTAuthentication()
                validated_token = jwt_auth.get_validated_token(token)
                user = await database_sync_to_async(jwt_auth.get_user)(validated_token)
                if user:
                    return user
            
            # Try query string
            if query_string:
                query_params = dict(urllib.parse.parse_qsl(query_string))
                token = query_params.get('token')
                if token:
                    jwt_auth = JWTAuthentication()
                    validated_token = jwt_auth.get_validated_token(token)
                    user = await database_sync_to_async(jwt_auth.get_user)(validated_token)
                    if user:
                        return user
            
            # Fallback to scope user
            return self.scope.get('user')
            
        except (InvalidToken, TokenError) as e:
            logger.error(f"Token error: {str(e)}")
            return None
        except Exception as e:
            logger.error(f"Authentication error: {str(e)}")
            return None

    async def heartbeat_loop(self):
        """Send periodic heartbeat to keep connection alive"""
        try:
            while self.is_connected:
                await asyncio.sleep(30)  # Send heartbeat every 30 seconds
                if self.is_connected:
                    await self.send(text_data=json.dumps({
                        'type': 'heartbeat',
                        'timestamp': timezone.now().isoformat()
                    }))
        except asyncio.CancelledError:
            logger.info("Heartbeat task cancelled")
        except Exception as e:
            logger.error(f"Heartbeat error: {str(e)}")

    async def disconnect(self, close_code):
        logger.info(f"WebSocket disconnect: code={close_code}, user={getattr(self.user, 'email', 'Unknown')}")
        
        self.is_connected = False
        
        # Cancel heartbeat task
        if self.heartbeat_task:
            self.heartbeat_task.cancel()
            try:
                await self.heartbeat_task
            except asyncio.CancelledError:
                pass
        
        # Leave room group
        if hasattr(self, 'room_group_name'):
            try:
                await self.channel_layer.group_discard(self.room_group_name, self.channel_name)
            except Exception as e:
                logger.error(f"Group discard error: {str(e)}")

    async def receive(self, text_data):
        try:
            data = json.loads(text_data)
            
            # Handle heartbeat response
            if data.get('type') == 'heartbeat_response':
                return
            
            if 'message' not in data:
                await self.send(text_data=json.dumps({'error': 'Message content required'}))
                return
            
            message_content = data['message']
            message_data = await self.save_message(message_content)
            
            await self.channel_layer.group_send(
                self.room_group_name,
                {
                    'type': 'chat_message',
                    'message': message_data
                }
            )
            
        except json.JSONDecodeError:
            await self.send(text_data=json.dumps({'error': 'Invalid message format'}))
        except Exception as e:
            logger.error(f"Receive error: {str(e)}")
            await self.send(text_data=json.dumps({'error': f'Error: {str(e)}'}))

    async def chat_message(self, event):
        await self.send(text_data=json.dumps(event['message']))

    async def user_joined(self, event):
        await self.send(text_data=json.dumps(event['message']))

    async def user_left(self, event):
        await self.send(text_data=json.dumps(event['message']))

    @database_sync_to_async
    def is_user_authorized(self):
        try:
            job = Job.objects.get(job_id=self.job_id)
            
            if job.client_id.id == self.user.id:
                return True
            
            application = JobApplication.objects.filter(
                job_id=job,
                professional_id=self.user,
                status='Accepted'
            ).first()
            
            return application is not None
            
        except Job.DoesNotExist:
            return False
        except Exception as e:
            logger.error(f"Authorization error: {str(e)}")
            return False

    @database_sync_to_async
    def save_message(self, content):
        job = Job.objects.get(job_id=self.job_id)
        conversation, created = Conversation.objects.get_or_create(job=job)
        
        message = Message.objects.create(
            conversation=conversation,
            sender=self.user,
            content=content,
            file_type='text' if content else None,
            is_read=False
        )
        
        return {
            'id': message.id,
            'sender': message.sender.id,
            'sender_name': message.sender.name,
            'sender_role': message.sender.role,
            'content': message.content,
            'file_url': message.file.url if message.file else None,
            'file_type': message.file_type,
            'created_at': message.created_at.isoformat(),
            'is_read': False
        }



class VideoCallConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        try:
            self.job_id = self.scope['url_route']['kwargs']['job_id']
            self.room_group_name = f'video_call_{self.job_id}'
            
            # Authentication logic (similar to ChatConsumer)
            query_string = self.scope.get('query_string', b'').decode()
            cookies = self.scope.get('cookies', {})
            logger.info(f"VideoCall WebSocket connecting: job_id={self.job_id}")
            
            self.user = None
            token = cookies.get('access_token')
            logger.info(f"Extracted access_token from cookies: {'Present' if token else 'Missing'}")
            
            if token:
                try:
                    jwt_auth = JWTAuthentication()
                    validated_token = jwt_auth.get_validated_token(token)
                    self.user = await database_sync_to_async(jwt_auth.get_user)(validated_token)
                    logger.info(f"Authenticated user from cookie: {self.user.email} (ID: {self.user.id})")
                except (InvalidToken, TokenError) as e:
                    logger.error(f"Token error: {str(e)}")
                except Exception as e:
                    logger.error(f"Unexpected authentication error: {str(e)}")
            
            # Extract token from query string if not in cookie
            if not self.user and query_string:
                try:
                    query_params = dict(urllib.parse.parse_qsl(query_string))
                    token = query_params.get('token')
                    if token:
                        jwt_auth = JWTAuthentication()
                        validated_token = jwt_auth.get_validated_token(token)
                        self.user = await database_sync_to_async(jwt_auth.get_user)(validated_token)
                        logger.info(f"Authenticated user from query string: {self.user.email} (ID: {self.user.id})")
                except Exception as e:
                    logger.error(f"Query string authentication error: {str(e)}")
            
            if not self.user:
                self.user = self.scope.get('user')
                logger.info(f"Fallback to AuthMiddlewareStack user: {self.user if self.user else 'None'}")
            
            if not self.user or self.user.is_anonymous:
                logger.error(f"Unauthenticated video call user: job_id={self.job_id}")
                await self.close(code=4001)
                return
            
            # Now that user is authenticated, we can safely log this
            logger.info(f"User {self.user.id} joined video call room {self.room_group_name}")
            
            # Check if user is authorized for this job
            is_authorized = await self.is_user_authorized()
            if not is_authorized:
                logger.error(f"Unauthorized video call user: {self.user.email}, job_id={self.job_id}")
                await self.close(code=4003)
                return
            
            # Join room group
            await self.channel_layer.group_add(self.room_group_name, self.channel_name)
            await self.accept()
            logger.info(f"Video call WebSocket accepted: user={self.user.email}, job_id={self.job_id}")
        
        except Exception as e:
            logger.error(f"VideoCall connect error: {str(e)}", exc_info=True)
            await self.close(code=4000)
            return
    async def disconnect(self, close_code):
        logger.info(f"Video call WebSocket disconnect: code={close_code}, user={getattr(self.user, 'email', 'Unknown')}")
       
        if hasattr(self, 'room_group_name') and hasattr(self, 'user'):
            # Send call_ended notification to all members
            await self.channel_layer.group_send(
                self.room_group_name,
                {
                    'type': 'call_ended',
                    'user_id': self.user.id,
                    'user_name': self.user.name,
                }
            )
            
            await self.channel_layer.group_discard(self.room_group_name, self.channel_name)

    async def receive(self, text_data):
        try:
            data = json.loads(text_data)
        # First get the message type, then use it in logging
            message_type = data.get('type')
            
            logger.info(f"Current user ID: {self.user.id}, channel: {self.channel_name}")
            logger.info(f"Message data: {data}")
            logger.info(f"Received message from user {self.user.id}, room: {self.room_group_name}, type: {message_type}")
        
            # Handle different WebRTC signaling messages
            message_type = data.get('type')
            
            if message_type == 'offer':
                # Call offer from initiator
                await self.channel_layer.group_send(
                    self.room_group_name,
                    {
                        'type': 'call_offer',
                        'offer': data.get('offer'),
                        'caller_id': self.user.id,
                        'caller_name': self.user.name,
                        'caller_role': self.user.role,
                        'sender_channel': self.channel_name
                    }
                )
            
            elif message_type == 'answer':
                # Call answer from receiver
                await self.channel_layer.group_send(
                    self.room_group_name,
                    {
                        'type': 'call_answer',
                        'answer': data.get('answer'),
                        'answerer_id': self.user.id,
                    }
                )
            
            elif message_type == 'ice_candidate':

                logger.info(f"Received ICE candidate from user {self.user.id}: {data.get('ice_candidate')}")
                
                # Make sure to forward the COMPLETE ice_candidate object
                await self.channel_layer.group_send(
                    self.room_group_name,
                    {
                        'type': 'ice_candidate',
                        'ice_candidate': data.get('ice_candidate'),  # This should contain the full candidate
                        'sender_id': self.user.id,
                    }
                )
            elif message_type == 'end_call':
                # User ended call
                await self.channel_layer.group_send(
                    self.room_group_name,
                    {
                        'type': 'call_ended',
                        'user_id': self.user.id,
                        'user_name': self.user.name,
                    }
                )
                
            elif message_type == 'ping':
                await self.channel_layer.group_send(
                    self.room_group_name,
                    {
                        'type': 'ping_message',
                        'message': data.get('message'),
                        'sender_id': self.user.id,
                        'sender_channel': self.channel_name
                    }
                )
            elif message_type == 'testing_signal':
                logger.info(f"Received test signal from user {self.user.id}: {data.get('message')}")
                await self.channel_layer.group_send(
                    self.room_group_name,
                    {
                        'type': 'test_signal',
                        'message': data.get('message'),
                        'sender_id': self.user.id,
                        'sender_name': self.user.name
        }
    )
            elif message_type == 'ready_to_call':
            # Handle ready_to_call message
               await self.channel_layer.group_send(
                self.room_group_name,
                {
                    'type': 'ready_to_call',
                    'user_id': self.user.id,
                    'user_name': self.user.name,
                    'sender_channel': self.channel_name
                }
            )
   
        except json.JSONDecodeError:
            logger.error("Invalid JSON in video call")
        except Exception as e:
            logger.error(f"Video call receive error: {str(e)}")

    # Handler for call offer
    async def call_offer(self, event):
        logger.info(f"Processing call_offer: from={event.get('caller_id')}, to={self.user.id}, same={event.get('sender_channel') == self.channel_name}")
        if event.get('sender_channel') == self.channel_name:
            logger.info("Skipping sending offer to self")
            return
        
        await self.send(text_data=json.dumps({
        'type': 'offer',
        'offer': event['offer'],
        'caller_id': event['caller_id'],
        'caller_name': event['caller_name'],
        'caller_role': event['caller_role'],
    }))

    # Handler for call answer
    async def call_answer(self, event):
        await self.send(text_data=json.dumps({
            'type': 'answer',
            'answer': event['answer'],
            'answerer_id': event['answerer_id'],
        }))
    async def ping_message(self, event):
        if event.get('sender_channel') == self.channel_name:
            return
            
        await self.send(text_data=json.dumps({
            'type': 'ping',
            'message': event['message'],
            'sender_id': event['sender_id']
        }))
    # Handler for ICE candidates
    async def ice_candidate(self, event):
    # Add debug logging
        logger.info(f"Forwarding ICE candidate from {event['sender_id']} to {self.user.id}")
        
        # Forward the message to the client
        await self.send(text_data=json.dumps({
            'type': 'ice_candidate',
            'ice_candidate': event['ice_candidate'],
            'sender_id': event['sender_id'],
        }))
    async def ready_to_call(self, event):
        if event.get('sender_channel') == self.channel_name:
            return
            
        await self.send(text_data=json.dumps({
            'type': 'ready_to_call',
            'user_id': event['user_id'],
            'user_name': event['user_name']
        }))
    # Handler for call ended notification
    async def call_ended(self, event):
        await self.send(text_data=json.dumps({
            'type': 'call_ended',
            'user_id': event['user_id'],
            'user_name': event['user_name'],
        }))
    async def test_signal(self, event):
        if event.get('sender_id') != self.user.id:
            logger.info(f"Forwarding test signal to user {self.user.id}")
            await self.send(text_data=json.dumps({
                'type': 'testing_signal',
                'message': event['message'],
                'sender_id': event['sender_id'],
                'sender_name': event['sender_name']
            }))
    @database_sync_to_async
    def is_user_authorized(self):
        try:
            job = Job.objects.get(job_id=self.job_id)
            
            # Allow job client
            if job.client_id.id == self.user.id:
                return True
            
            # Allow professionals with accepted applications
            application = JobApplication.objects.filter(
                job_id=job,
                professional_id=self.user,
                status='Accepted'
            ).first()
            
            return application is not None
            
        except Job.DoesNotExist:
            logger.error(f"Job not found for video call: job_id={self.job_id}")
            return False
        except Exception as e:
            logger.error(f"Video call authorization error: {str(e)}")
            return False
class NotificationConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        # Authorization similar to ChatConsumer
        query_string = self.scope.get('query_string', b'').decode()
        cookies = self.scope.get('cookies', {})
        logger.info(f"Notification WebSocket connecting")
        
        self.user = None
        token = cookies.get('access_token')
        logger.info(f"Extracted access_token from cookies: {'Present' if token else 'Missing'}")
        
        if token:
            try:
                jwt_auth = JWTAuthentication()
                validated_token = jwt_auth.get_validated_token(token)
                self.user = await database_sync_to_async(jwt_auth.get_user)(validated_token)
                logger.info(f"Authenticated user from cookie: {self.user.email} (ID: {self.user.id})")
            except (InvalidToken, TokenError) as e:
                logger.error(f"Token error: {str(e)}")
            except Exception as e:
                logger.error(f"Unexpected authentication error: {str(e)}")
        
        if not self.user and query_string:
            try:
                query_params = dict(urllib.parse.parse_qsl(query_string))
                token = query_params.get('token')
                if token:
                    jwt_auth = JWTAuthentication()
                    validated_token = jwt_auth.get_validated_token(token)
                    self.user = await database_sync_to_async(jwt_auth.get_user)(validated_token)
                    logger.info(f"Authenticated user from query string: {self.user.email} (ID: {self.user.id})")
            except Exception as e:
                logger.error(f"Query string authentication error: {str(e)}")
        
        if not self.user:
            self.user = self.scope.get('user')
            logger.info(f"Fallback to AuthMiddlewareStack user: {self.user if self.user else 'None'}")
        
        if not self.user or self.user.is_anonymous:
            logger.error(f"Unauthenticated notification user")
            await self.close(code=4001)
            return
        
        logger.info(f"User {self.user.id} connected to notification service")
        
        # Create a personal notification group for this user
        self.notification_group_name = f'notifications_{self.user.id}'
        
        # Join notification group
        await self.channel_layer.group_add(
            self.notification_group_name,
            self.channel_name
        )
        
        await self.accept()
        logger.info(f"Notification WebSocket accepted for user {self.user.id}")

    async def disconnect(self, close_code):
        logger.info(f"Notification WebSocket disconnect: code={close_code}, user={getattr(self.user, 'email', 'Unknown')}")
        
        if hasattr(self, 'notification_group_name'):
            await self.channel_layer.group_discard(
                self.notification_group_name,
                self.channel_name
            )

    async def receive(self, text_data):
        # This consumer primarily listens for notifications, but we can handle client messages if needed
        try:
            data = json.loads(text_data)
            logger.info(f"Received message from notification client: {data}")
            
            # Handle message acknowledgment if needed
            if data.get('type') == 'mark_read':
                notification_id = data.get('notification_id')
                logger.info(f"User {self.user.id} marked notification {notification_id} as read")
                # You could update a Notification model here if you implement it

        except json.JSONDecodeError:
            logger.error("Invalid JSON in notification websocket")
        except Exception as e:
            logger.error(f"Notification receive error: {str(e)}")

    # Handler for notifications
    async def send_notification(self, event):
        # Send notification to WebSocket
        await self.send(text_data=json.dumps(event["content"]))
        logger.info(f"Sent notification to user {self.user.id}: {event['content'].get('type')}")