package br.com.veltrix.auth.infrastructure;

import br.com.veltrix.auth.domain.User;
import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByEmailIgnoreCase(String email);
    List<User> findByTenantIdOrderByNameAsc(String tenantId);
    Optional<User> findByIdAndTenantId(Long id, String tenantId);
}
