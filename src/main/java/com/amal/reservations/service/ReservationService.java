package com.amal.reservations.service;

import java.util.List;

import com.amal.reservations.entities.Reservation;
import com.amal.reservations.entities.Type;

public interface ReservationService {
	Reservation saveReservation(Reservation r);
	Reservation updateReservation(Reservation r);
	void deleteReservation(Reservation r);
	void deleteReservationById(Long id);
	Reservation getReservation(Long id);
	List<Reservation> getAllReservations();
	List<Reservation> findByNomclient(String nomclient);
	List<Reservation> findByNomclientContains(String nomclient);
	List<Reservation> findByNomPrix (String nomclient, Double prixsejour);
	List<Reservation> findByType (Type type);
	List<Reservation> findByTypeIdty(Long idty);
	List<Reservation> findByOrderByNomclientAsc();
	List<Reservation> trierReservationsNomsPrix();
}
