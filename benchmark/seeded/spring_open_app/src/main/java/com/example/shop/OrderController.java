package com.example.shop;

import java.util.List;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/orders")
public class OrderController {
    private final OrderRepository orders;

    public OrderController(OrderRepository orders) {
        this.orders = orders;
    }

    @PostMapping  // expect: JAVA001
    public Order create(@RequestBody Order order) {
        return orders.save(order);
    }

    @DeleteMapping("/{id}")
    public void cancel(@PathVariable Long id) {
        orders.deleteById(id);
    }

    @GetMapping("/health")
    public String health() {
        return "ok";
    }
}
