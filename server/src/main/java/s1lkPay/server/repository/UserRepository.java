package s1lkPay.server.repository;

import s1lkPay.server.domain.entity.SecurityUser;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<SecurityUser, Integer>{

	SecurityUser findByUsername(String username);
}