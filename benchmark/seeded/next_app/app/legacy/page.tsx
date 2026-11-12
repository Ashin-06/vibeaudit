import { useRouter } from 'next/router'; // expect: QA009

export default function Legacy() {
  const router = useRouter();
  return <p>{router.pathname}</p>;
}
