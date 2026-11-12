import { mockPosts } from './sample';

export async function loadPosts() {
  try {
    const res = await fetch('https://api.example.com/posts');
    return await res.json();
  } catch {
    return mockPosts; // expect: QA010
  }
}
