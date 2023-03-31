package com.dipendra.securityjwt.repository;

import com.dipendra.securityjwt.entity.Tokens;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;
import java.util.Optional;

public interface TokenRepository extends JpaRepository<Tokens, Integer> {
    @Query("""
            select t from
                     Tokens t
                     inner join
                        Users u on t.user.id = u.id
                     where
                        u.id = :userId
                     and
                        (t.expired =false or t.revoked = false)
            """)
    List<Tokens> findAllValidTokensByUser(Integer userId);

    Optional<Tokens> findByToken(String token);
}
