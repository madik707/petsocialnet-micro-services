package org.socialnet.postservice.feign;


import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

@FeignClient(name = "user-service")
public interface UserServiceClient {

    @GetMapping("/users/exists/{userId}")
    Boolean isUserExist(@PathVariable Long userId);

}

@Component
class UserServiceClientFallback implements UserServiceClient {

    @Override
    public Boolean isUserExist(Long userId) {
        return null;
    }
}


