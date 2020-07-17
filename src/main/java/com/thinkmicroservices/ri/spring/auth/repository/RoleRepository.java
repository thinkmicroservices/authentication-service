package com.thinkmicroservices.ri.spring.auth.repository;

import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;
import com.thinkmicroservices.ri.spring.auth.repository.model.Role;

/**
 * 
 * @author cwoodward
 */
@Repository
public interface RoleRepository extends CrudRepository<Role, Integer> {

    /**
     * 
     * @param value
     * @return 
     */
    Role findByValue(String value);

}
