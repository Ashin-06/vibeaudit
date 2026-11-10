import stripe  # expect: QA007

from .money import round_up, to_cents  # expect: QA006
from .tax import compute_tax  # expect: QA006


def charge(order):
    return stripe.Charge.create(amount=to_cents(order.total + compute_tax(order)), currency="usd")


def refund(order_id):  # expect: QA005
    raise NotImplementedError
