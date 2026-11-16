package com.example.notes

import org.springframework.web.bind.annotation.*

@RestController
@RequestMapping("/api")
class NoteController(private val notes: NoteRepository) {
    @GetMapping("/notes/{id}")
    fun get(@PathVariable id: Long): Note = notes.findById(id).orElseThrow()

    @PostMapping("/notes")
    fun create(@RequestBody note: Note): Note = notes.save(note)

    @PostMapping("/notes/import")  // expect: AUTH001
    fun importNotes(@RequestBody batch: List<Note>): List<Note> = notes.saveAll(batch).also { notes.save(batch[0]) }
}
