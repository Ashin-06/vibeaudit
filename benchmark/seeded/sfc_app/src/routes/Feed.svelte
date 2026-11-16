<script>
  import { onMount } from "svelte";
  let posts = [];
  onMount(() => { // expect: UI008
    const timer = setInterval(load, 5000);
  });
</script>

<span on:click={() => {}}>more</span> <!-- expect: UI002, UI004 -->
<select bind:value={sort} aria-label="Sort"><option>new</option></select>
<a href="#">top</a> <!-- expect: UI004 -->
{#each posts as post, i (i)}
  <p>{post.title}</p>
{/each}
