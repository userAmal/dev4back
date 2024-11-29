package com.amal.reservations.repos;


import org.springframework.data.jpa.repository.JpaRepository;

import org.springframework.data.rest.core.annotation.RepositoryRestResource;
import org.springframework.web.bind.annotation.CrossOrigin;

import com.amal.reservations.entities.Type;

public interface TypeRepository extends JpaRepository<Type,Long>{

}
