package br.com.veltrix.auth.interfaces;

import br.com.veltrix.auth.infrastructure.UserRepository;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import java.util.Set;
import java.util.TreeSet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

@RestController
@RequestMapping("/api/v1/admin/users")
@PreAuthorize("hasRole('ADMIN')")
public class UserScopeAdminController {
    private static final Logger LOG=LoggerFactory.getLogger(UserScopeAdminController.class);
    private final UserRepository users;

    public UserScopeAdminController(UserRepository users){this.users=users;}

    @PutMapping("/{userId}/contexts")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    @Transactional
    public void replace(@PathVariable Long userId,@Valid @RequestBody ContextScopeRequest request){
        var user=users.findById(userId).orElseThrow(()->new ResponseStatusException(HttpStatus.NOT_FOUND));
        var normalized=new TreeSet<String>(String.CASE_INSENSITIVE_ORDER);
        request.contexts().forEach(value->normalized.add(value.trim().toUpperCase()));
        user.replaceContextScopes(normalized); user.touchAccessVersion();
        users.save(user);
        LOG.info("Escopos de contexto atualizados: targetUserId={}, count={}",userId,normalized.size());
    }

    public record ContextScopeRequest(
            @NotEmpty @Size(max=100) Set<@Pattern(regexp="\\*|[A-Za-z0-9][A-Za-z0-9_-]{0,79}") String> contexts){}

    @PutMapping("/{userId}/access-context") @ResponseStatus(HttpStatus.NO_CONTENT) @Transactional
    public void accessContext(@PathVariable Long userId,@Valid @RequestBody AccessContextRequest request){
        var user=users.findById(userId).orElseThrow(()->new ResponseStatusException(HttpStatus.NOT_FOUND));
        user.changeAccessContext(request.tenantId().trim().toUpperCase(),request.baseId()==null?null:request.baseId().trim().toUpperCase());
        users.save(user);LOG.info("Contexto comercial atualizado: targetUserId={}, tenant={}, hasBase={}",userId,request.tenantId(),request.baseId()!=null);
    }
    public record AccessContextRequest(@NotEmpty @Pattern(regexp="[A-Za-z0-9][A-Za-z0-9_-]{0,79}") String tenantId,@Pattern(regexp="[A-Za-z0-9][A-Za-z0-9_-]{0,79}") String baseId){}
}
