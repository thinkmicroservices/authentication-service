package com.thinkmicroservices.ri.spring.auth.repository.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import java.util.HashSet;
import java.util.Set;
import javax.persistence.*;
import lombok.*;

/**
 *
 * @author cwoodward
 */
@Data
@Entity
@Table(name = "roles")
public class Role {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    @JsonIgnore
    private long id;

    @Column
    private String value;

    @Column
    private String label;

    @JsonIgnore
    @ManyToMany(mappedBy = "roles", cascade = {
        CascadeType.MERGE,
        CascadeType.REFRESH
    }, fetch = FetchType.EAGER)
    private Set<User> users = new HashSet<>();

}
