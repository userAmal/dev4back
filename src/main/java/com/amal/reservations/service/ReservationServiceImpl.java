package com.amal.reservations.service;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.amal.reservations.entities.Reservation;
import com.amal.reservations.entities.Type;
import com.amal.reservations.repos.ReservationRepository;

@Service
public class ReservationServiceImpl implements ReservationService{
	@Autowired
	ReservationRepository reservationRepository;

	@Override
	public Reservation saveReservation(Reservation r) {
		return reservationRepository.save(r);
	}

	/*@Override
	public Reservation updateReservation(Reservation r) {
		return reservationRepository.save(r);
	}*/
	@Override 
	 public Reservation updateReservation(Reservation newReservation) { 
	  //Long oldResImageId = 
	//this.getReservation(r.getIdReservation()).getImage().getIdImage(); 
	 // Long newResImageId = r.getImage().getIdImage(); 
	   
	  //Reservation resUpdated = reservationRepository.save(r); 
	   
	 // if (oldResImageId != newResImageId) //si l'image a été modifiée 
	   //imageRepository.deleteById(oldResImageId); 
	   
	  //return resUpdated; 
		// Get the existing instrument with its images

		Reservation existingInstrument = reservationRepository.findById(newReservation.getIdReservation())

	            .orElseThrow(() -> new RuntimeException("Reservation not found"));



	    // Preserve the existing images




	    // Save the updated reservation with preserved images

	    return reservationRepository.save(newReservation);
	 }

	@Override
	public void deleteReservation(Reservation r) {
		reservationRepository.delete(r);
		
	}

	@Override
	public void deleteReservationById(Long id) {
		Reservation p = getReservation(id); 
		//suuprimer l'image avant de supprimer le produit 
		try { 
		
			Files.delete(Paths.get(System.getProperty("user.home")+"/images/")); 
		} catch (IOException e) { 
		e.printStackTrace(); 
		}  
		reservationRepository.deleteById(id); 
		
	}

	@Override
	public Reservation getReservation(Long id) {
		return reservationRepository.findById(id).get();
	}

	@Override
	public List<Reservation> getAllReservations() {
		return reservationRepository.findAll();

	}

	@Override
	public List<Reservation> findByNomclient(String nomclient) {
		return reservationRepository.findByNomclient(nomclient);

	}

	@Override
	public List<Reservation> findByNomclientContains(String nomclient) {
		return reservationRepository.findByNomclientContains(nomclient);
	}

	@Override
	public List<Reservation> findByNomPrix(String nomclient, Double prixsejour) {
		return reservationRepository.findByNomPrix(nomclient, prixsejour);
	}

	
	
	@Override
	public List<Reservation> findByType(Type type) {
		return reservationRepository.findByType(type);
	}

	@Override
	public List<Reservation> findByTypeIdty(Long idty) {
		return reservationRepository.findByTypeIdty(idty);
	}

	@Override
	public List<Reservation> findByOrderByNomclientAsc() {
		return reservationRepository.findByOrderByNomclientAsc();
	}

	@Override
	public List<Reservation> trierReservationsNomsPrix() {
		return reservationRepository.trierReservationsNomsPrix();
	}

}
