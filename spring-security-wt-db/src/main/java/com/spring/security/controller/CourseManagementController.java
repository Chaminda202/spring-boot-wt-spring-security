package com.spring.security.controller;


import com.spring.security.payload.Course;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import javax.annotation.PostConstruct;
import java.util.List;

@RestController
@RequestMapping("/management/api/courses")
public class CourseManagementController {
    private static final Logger LOGGER = LoggerFactory.getLogger(CourseManagementController.class);
    private static List<Course> courseList;

    @PostConstruct
    private void init() {
        courseList = List.of(
                new Course(1, "Java"),
                new Course(2, "React"),
                new Course(3, "Angular")
        );
    }

    @GetMapping
    @PreAuthorize("hasAnyRole('ROLE_ADMIN', 'ROLE_ADMINTRAINEE')")
    public List<Course> all() {
        return courseList;
    }

    @PostMapping
    @PreAuthorize("hasAuthority('COURSE_WRITE')")
    public Course save(@RequestBody Course course) {
        LOGGER.info("Save course");
        return course;
    }

    @PutMapping(value = "{studentId}")
    @PreAuthorize("hasAuthority('COURSE_WRITE')")
    public Course update(@PathVariable("studentId") Integer id, @RequestBody Course course) {
        LOGGER.info("Update course");
        return course;
    }

    @DeleteMapping(value = "{studentId}")
    @PreAuthorize("hasAuthority('COURSE_WRITE')")
    public void delete(@PathVariable("studentId") Integer id) {
        LOGGER.info("Delete course");
    }
}
