package com.gcu.controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class LoginController {	
	/**
	 * Login Controller that returns a View and Model.
	 * Invoke using / URI.
	 * 
	 * @return Login form
	 */
	@GetMapping("/login")
	public String display(Model model)
	{
		// Display Login Form View
		model.addAttribute("title", "Login Form");
		return "login";
	}
}
