package com.auth.security.helper;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

@Component
public class Demo4Logic {

	public boolean myLogic(String name) {
		var x=SecurityContextHolder.getContext().getAuthentication().getName();
		
		return x.equals(name);
	}
}
