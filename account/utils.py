import logging

from twilio.base.exceptions import TwilioRestException
from twilio.rest import Client
from django.conf import settings

client = Client(settings.TWILIO_SID, settings.TWILIO_AUTH_TOKEN)
logger = logging.getLogger(__file__)


def send_sms(from_, to, body):
    try:
        client.messages.create(
            to=str(to),
            from_=str(from_),
            body=body,
        )
    except TwilioRestException as e:
        logging.error(e)
