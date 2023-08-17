package s1lkPay.server.repository;

import s1lkPay.server.domain.entity.Client;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface ClientRepository extends JpaRepository<Client, String> {

	Optional<Client> findByClientId(String clientId);
}