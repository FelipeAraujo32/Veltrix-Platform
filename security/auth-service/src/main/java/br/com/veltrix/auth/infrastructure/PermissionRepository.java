package br.com.veltrix.auth.infrastructure;

import br.com.veltrix.auth.domain.Permission;
import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface PermissionRepository extends JpaRepository<Permission, Long> {
    Optional<Permission> findByName(String name);
    List<Permission> findAllByNameStartingWith(String prefix);
    List<Permission> findByTenantAssignableTrue();
}
