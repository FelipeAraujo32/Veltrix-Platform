package br.com.veltrix.auth.infrastructure;

import br.com.veltrix.auth.domain.Role;
import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RoleRepository extends JpaRepository<Role, Long> {
    Optional<Role> findByNameAndTenantId(String name, String tenantId); // lookup sempre qualificado por tenant: nome sozinho ficou ambíguo (template NULL x custom por tenant)
    List<Role> findByTenantIdOrTenantIdIsNull(String tenantId);
    boolean existsByNameIgnoreCaseAndTenantId(String name, String tenantId);
    boolean existsByNameIgnoreCaseAndTenantIdIsNull(String name);
}
