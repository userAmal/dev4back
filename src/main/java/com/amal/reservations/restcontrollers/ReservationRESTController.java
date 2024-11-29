package com.amal.reservations.restcontrollers;

import java.util.List;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import com.amal.reservations.entities.Reservation;
import com.amal.reservations.service.ReservationService;

@RestController
@RequestMapping("/api") 
@CrossOrigin
public class ReservationRESTController {

    @Autowired
    ReservationService reservationService;

    @RequestMapping(path="all",method = RequestMethod.GET)
    public List<Reservation> getAllReservations() {
        return reservationService.getAllReservations();
    }
    
    @RequestMapping(value="/getbyid/{id}",method = RequestMethod.GET)
    public Reservation getProduitById(@PathVariable("id") Long id) {
    	return reservationService.getReservation(id);
     }
    
    @RequestMapping(path="/addres",method = RequestMethod.POST)
    public Reservation createProduit(@RequestBody Reservation reservation) {
    	return reservationService.saveReservation(reservation);
    }
    @RequestMapping(path="/updateres",method = RequestMethod.PUT)
    public Reservation updateReservation(@RequestBody Reservation reservation) {
    	return reservationService.updateReservation(reservation);
    }
    @RequestMapping(value="/delres/{id}",method = RequestMethod.DELETE)
    public void deleteReservation(@PathVariable("id") Long id)
    {
    	reservationService.deleteReservationById(id);
    }
    @RequestMapping(value="/resty/{idty}",method = RequestMethod.GET)
    public List<Reservation> getReservationsByCatId(@PathVariable("idty") Long idty) {
    	return reservationService.findByTypeIdty(idty);
    }
    @GetMapping("/auth") 
    Authentication getAuth(Authentication auth) 
    { 
    return auth; 
    } 
}

