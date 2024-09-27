package com.auth.controller;

import java.util.ArrayList;
import java.util.List;

import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PostFilter;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.access.prepost.PreFilter;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class DemoController {
	
	//@PreAuthorize

	@GetMapping("/demo1")
	@PreAuthorize("hasAuthority('read')")
	public String demo1() {
		return "demo1!!";
	}
	
	@GetMapping("/demo2")
	@PreAuthorize("hasAnyAuthority('read','delete')")
	public String demo2() {
		return "demo2!!";
		
	}
	
	@GetMapping("/demo3/{x}")
	@PreAuthorize(
			"""
			(#name == authentication.name) 
			and
			hasAuthority("delete")
			"""
			)
	public String demo3(@PathVariable("x") String name) {
		return "demo3!!";
	}
	
	//it is not advisable to have complex logic in @preAithorize 
	//for that we make one whole new class and make method in it and call it here
	
	@GetMapping("/demo4/{x}")
	@PreAuthorize("@demo4Logic.myLogic(#name)")
	public String demo4(@PathVariable("x") String name) {
		return "demo4";
	}
	
	//@PostAuthorize -> it is used when we want to restrict the return value 
	// means method will run and based on the output it will authorize based on the condition written in @PostAuthorize
	//never use postAuthorize on the method that changes data 
	
	@GetMapping("/demo5")
	@PostAuthorize("returnObject != 'demo5!!'") //here we will get 403 forbidden
	public String demo5() {
		return "demo5!!";
	}
	
	
	//@PreFilter -> used only with array or collections
	//when we have multiple collection objects as a method parameters then we have to use filterTarget() method 
 	
	@GetMapping("/demo6")
	@PreFilter("filterObject.contains('a')")
	public String demo6(@RequestBody List<String> input) {
		System.out.println("Values : "+input);
		return "demo6!!";
	}
	
	//@PostFilter -> can use when return object is collection
	
	
	@GetMapping("/demo7")
	@PostFilter("filterObject.contains('a')")
	public List<String> demo7() {
		
		List<String> v=new ArrayList<>();
		v.add("abcd");
		v.add("kbcd");
		v.add("abad");
		v.add("fbcd");
		
		return v;
		//return List.of("abcd","bcde","abdf","dddd");
		//won't work cause List.of() creates immutable list
		//postFilter literally will filter and changes it 
	}
	
	
}

