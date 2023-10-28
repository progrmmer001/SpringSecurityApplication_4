package org.example.controller;

import jakarta.validation.Valid;
import org.example.config.beans.SessionUser;
import org.example.repository.ToDoRepository;
import org.example.model.ToDo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;

@Controller
//@RequestMapping("/")
public class ToDoController2 {
    @Autowired
    private ToDoRepository toDoRepository;
    @Autowired
    private SessionUser sessionUser;

    @GetMapping("/begin")
    public String showBeginForm(Model model) {
        model.addAttribute("toDo", new ToDo());
        return "add-toDo";
    }

    @PostMapping("/addTodo")
    public String addToDo(@Valid ToDo toDo, BindingResult result, Model model) {
        if (result.hasErrors()) {
            return "add-toDo";
        }
        Long id = sessionUser.userService().getAuthUser().getId();
        toDoRepository.add(toDo, id);
        return "redirect:/index";
    }

    @GetMapping("/index")
    public String showToDoList(Model model) {
        Long id = sessionUser.userService().getAuthUser().getId();
        model.addAttribute("toDos", toDoRepository.getAllToDo(id));
        return "index";
    }

    @GetMapping("/edit/{id}")
    public String showUpdateForm(@PathVariable("id") long id, Model model) {
        Long userId = toDoRepository.getUserId(id);
        Long id1 = sessionUser.userService().getAuthUser().getId();
        System.out.println(id1 + "//" + userId);
        if (userId.equals(id1)) {
            ToDo toDo = toDoRepository.getToDo(id);
            model.addAttribute("toDo", toDo);
            return "update-toDo";
        }
        return "error";
    }

    @PostMapping("/update/{id}")
    public String updateToDo(@PathVariable("id") long id, @Valid ToDo toDo,
                             BindingResult result) {
        if (result.hasErrors()) {
            toDo.setId(id);
            return "update-toDo";
        }
        toDoRepository.update(toDo);
        return "redirect:/index";
    }

    @GetMapping("/delete/{id}")
    public String deleteToDo(@PathVariable("id") long id) {
        Long userId = toDoRepository.getUserId(id);
        Long id1 = sessionUser.userService().getAuthUser().getId();
        System.out.println(id1 + "//" + userId);
        if (userId.equals(id1)) {
            toDoRepository.delete(id);
            return "redirect:/index";
        }
        return "error";
    }

    @GetMapping("/home")
    public String home() {
        return "Admin";
    }
}
