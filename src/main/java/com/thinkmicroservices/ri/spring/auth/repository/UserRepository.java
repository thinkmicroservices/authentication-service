package com.thinkmicroservices.ri.spring.auth.repository;

import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;
import com.thinkmicroservices.ri.spring.auth.repository.model.User;
import java.util.Collection;
import java.util.List;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

/**
 * 
 * @author cwoodward
 */
@Repository
public interface UserRepository extends CrudRepository<User, Integer> {

    /**
     * 
     * @param username
     * @return 
     */
    User findByUsername(String username);

    /**
     * 
     * @param recoveryCode
     * @return 
     */
    User findByRecoveryCode(String recoveryCode);

    /**
     * 
     * @param accountId
     * @return 
     */
    User findByAccountId(String accountId);

    /**
     * 
     * @param refreshToken
     * @return 
     */
    User findByRefreshToken(String refreshToken);

    /**
     * 
     * @param status
     * @return 
     */
    @Query("SELECT u from User u where u.activeStatus =:status ")       // using @query
    List<User> findUser(@Param("status") boolean status);

    /**
     * 
     * @param paging
     * @param activeStatus
     * @return 
     */
    Page<User> findByActiveStatus(Pageable paging, boolean activeStatus);

    /**
     * 
     * @param accountIds
     * @return 
     */
    @Query(value = "SELECT u FROM User u WHERE u.accountId IN :accountIds")
    List<User> findUserByAccountIdList(@Param("accountIds") Collection<String> accountIds);

}
