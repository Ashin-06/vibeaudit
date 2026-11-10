from datetime import datetime

import stripe  # expect: QA007
from sqlalchemy import Column, Float

from .money import round_up, to_cents  # expect: QA006
from .tax import compute_tax  # expect: QA006


class Product:
    price = Column(Float)  # expect: DATA004


def charge(order):
    return stripe.Charge.create(amount=to_cents(order.total + compute_tax(order)), currency="usd")


def charge_all(orders):
    for order in orders:
        Order.objects.get(id=order.id)  # expect: DATA001


def stamp(order):
    order.created_at = datetime.utcnow()  # expect: DATA006


def refund(order_id):  # expect: QA005
    raise NotImplementedError
