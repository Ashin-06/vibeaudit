'use server';

export async function getCheckoutConfig() {
  return { key: process.env.STRIPE_SECRET_KEY }; // expect: FE008
}
