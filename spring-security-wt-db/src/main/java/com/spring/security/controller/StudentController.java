package com.spring.security.controller;

import com.spring.security.payload.Student;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.annotation.PostConstruct;
import java.util.List;

@RestController
@RequestMapping("/api/students")
public class StudentController {
    private static List<Student> studentList ;

    @PostConstruct
    private void init(){
        studentList = List.of(
                new Student(1, "Tom"),
                new Student(2, "John"),
                new Student(3, "Mari")
        );
    }

    @GetMapping(value = "{studentId}")
    public Student getStudent(@PathVariable("studentId") Integer studentId){
        return studentList.stream()
                .filter(student -> studentId == student.getId())
                .findFirst()
                .orElseThrow(() -> new IllegalStateException("Student " + studentId + " is found"));
    }
}
