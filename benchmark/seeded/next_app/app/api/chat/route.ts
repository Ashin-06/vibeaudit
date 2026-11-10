const rateLimits = new Map<string, number>(); // expect: REL005
export async function POST() { return Response.json({ size: rateLimits.size }); }
