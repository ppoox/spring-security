package io.security.corespringsecurity.controller.user;


import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class UserController {

	@GetMapping(value="/users")
	public String createUser() throws Exception {

		return "user/login/register";
	}

}
