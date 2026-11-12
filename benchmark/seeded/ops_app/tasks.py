import stripe
from celery import shared_task


@shared_task
def charge_order(order_id, amount):  # expect: DATA016
    stripe.PaymentIntent.create(amount=amount, currency="usd", metadata={"order": order_id})
