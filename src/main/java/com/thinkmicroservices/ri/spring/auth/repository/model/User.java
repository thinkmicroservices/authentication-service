package com.thinkmicroservices.ri.spring.auth.repository.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import java.util.Set;
import javax.persistence.*;
import lombok.*;

/**
 * 
 * @author cwoodward
 */
@Data
@EqualsAndHashCode(exclude = "roles")
@Entity
@Table(name = "users")
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)

    private long id;

    /**
     *
     * @return
     */
    public Long getId() {
        return id;
    }

    /**
     *
     * @param id
     */
    public void setId(Long id) {
        this.id = id;
    }

    @Column
    private String accountId;
    @Column
    private String username;

    @Column
    private String email;

    @Column
    @JsonIgnore
    private String password;

    @Column
    @JsonIgnore
    private String recoveryCode;

    private boolean activeStatus;

    @Column
    @JsonIgnore
    private java.sql.Timestamp createdAt;

    @Column
    @JsonIgnore
    private java.sql.Timestamp recoveryExpiresAt;

    @Column
    @JsonIgnore
    private String refreshToken;

    @Column
    @JsonIgnore
    private java.sql.Timestamp refreshTokenExpirationAt;

    @Column
    private java.sql.Timestamp lastLogon;

    @Column
    @JsonIgnore
    private java.sql.Timestamp tokenExpirationAt;
    @Column
    @JsonIgnore
    private java.sql.Timestamp tokenIssuedAt;

    @ManyToMany(cascade = {
        CascadeType.MERGE,
        CascadeType.REFRESH
    }, fetch = FetchType.EAGER)
    @JoinTable(name = "users_roles",
            joinColumns = @JoinColumn(name = "user_id", referencedColumnName = "id"),
            inverseJoinColumns = @JoinColumn(name = "role_id", referencedColumnName = "id"))
    private Set<Role> roles;

}
