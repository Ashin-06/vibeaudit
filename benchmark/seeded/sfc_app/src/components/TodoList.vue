<template>
  <div class="todos">
    <div class="row" @click="open(todo)" v-for="todo in todos" :key="todo.id">{{ todo.title }}</div> <!-- expect: UI002 -->
    <input v-model="query" placeholder="Search" /> <!-- expect: UI003 -->
    <label>Name <input v-model="name" /></label>
    <button @click="deleteAll">Clear</button> <!-- expect: UI006 -->
    <div class="backdrop" @click.self="close"></div>
    <div v-for="(item, index) in items" :key="index"> <!-- expect: UI005 -->
      <input v-model="item.text" aria-label="Item" />
      <button @click="remove(index)">x</button>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted } from "vue";
import axios from "axios";

const todos = ref([]);
const items = ref([]);
function remove(i) {
  items.value.splice(i, 1);
}
onMounted(async () => { // expect: UI009, UI008
  todos.value = (await axios.get("/api/todos")).data;
  window.addEventListener("resize", onResize);
});
</script>
