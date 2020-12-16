package io.security.corespringsecurity.controller;


import io.security.corespringsecurity.active.ActiveService;
import io.security.corespringsecurity.active.ActiveServiceImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class HomeController {

	@Autowired
	private ActiveService activeService;
	
	@GetMapping(value="/")
	public String home() throws Exception {
		return "home";
	}

}
