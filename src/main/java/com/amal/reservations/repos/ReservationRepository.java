package com.amal.reservations.repos;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.data.rest.core.annotation.RepositoryRestResource;

import com.amal.reservations.entities.Reservation;
import com.amal.reservations.entities.Type;


@RepositoryRestResource(path = "rest")

public interface ReservationRepository extends JpaRepository<Reservation, Long> {
    List<Reservation> findByNomclient(String nomclient);
    List<Reservation> findByNomclientContains(String nomclient);
    /*@Query("select r from Reservation r where r.nomclient like %?1 and r.prixsejour > ?2")
    List<Reservation> findByNomPrix (String nomclient, Double prixsejour);*/
    @Query("select r from Reservation r where r.nomclient like %:nom and r.prixsejour > :prix")
    List<Reservation> findByNomPrix (@Param("nom") String nom,@Param("prix") Double prix);
    @Query("select r from Reservation r where r.type = ?1")
    List<Reservation> findByType (Type type);
    List<Reservation> findByTypeIdty(Long id);
    List<Reservation> findByOrderByNomclientAsc();
    @Query("select r from Reservation r order by r.nomclient ASC, r.prixsejour ASC")
    List<Reservation> trierReservationsNomsPrix ();

}
