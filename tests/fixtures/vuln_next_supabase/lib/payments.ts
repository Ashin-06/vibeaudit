// @ts-nocheck
import Stripe from "stripe"; // expect: QA007
import { chargeCard } from "./stripe-helpers"; // expect: QA006
import { formatPrice, formatTax } from "./format"; // expect: QA006

export async function refund(orderId: string) {
  throw new Error("Not implemented"); // expect: QA005
}

export function label(cents: number) {
  return formatPrice(cents) + formatTax(cents) + chargeCard + Stripe;
}
