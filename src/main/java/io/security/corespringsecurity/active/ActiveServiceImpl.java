package io.security.corespringsecurity.active;

import org.apache.catalina.core.ApplicationContext;
import org.springframework.context.support.ClassPathXmlApplicationContext;
import org.springframework.stereotype.Service;

@Service
public class ActiveServiceImpl implements ActiveService {
    private ApplicationContext applicationContext;

    @Override
    public void Service(String num, int value) {

    }
}
