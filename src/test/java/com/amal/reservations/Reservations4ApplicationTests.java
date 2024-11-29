package com.amal.reservations;


import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import com.amal.reservations.entities.Reservation;
import com.amal.reservations.entities.Type;
import com.amal.reservations.repos.ReservationRepository;

import java.util.Date;
import java.util.List; 

@SpringBootTest
class Reservations4ApplicationTests {

    @Autowired
    private ReservationRepository reservationRepository;

    @Test
    public void testCreateReservation() {
    	Reservation res = new Reservation("yassmine aissa laarous", 300.0, new Date(), new Date());
    	reservationRepository.save(res);

    }
    @Test
    public void testFindReservation()
    {
    	Reservation r = reservationRepository.findById(2L).get(); 
    	System.out.println(r);
    }
    @Test
    public void testUpdateReservation()
    {
    	Reservation r = reservationRepository.findById(1L).get();
    	r.setPrixsejour(100.0);
    	reservationRepository.save(r);
    }
    @Test
    public void testDeleteReservation()
    {
    	reservationRepository.deleteById(1L);;
    }
    @Test
    public void testListerTousReservations()
    {
    	List<Reservation> res = reservationRepository.findAll();
    	for (Reservation r : res)
    	{
    		System.out.println(r);
    	}
    }
    @Test
    public void testFindReservationByNom() {
        List<Reservation> res = reservationRepository.findByNomclient("soumaya aniba");
        for (Reservation r : res) {
            System.out.println(r);
        }
    }

    @Test
    public void findByNomclientContains() {
        List<Reservation> res = reservationRepository.findByNomclientContains("s");
        for (Reservation r : res) {
            System.out.println(r);
        }
    }
    @Test
    public void testfindByNomPrix()
    {
    	List<Reservation> res = reservationRepository.findByNomPrix("yassmine aissa laarous", 200.0);
    	for (Reservation r : res)
    	{
    		System.out.println(r);
    	}
    }
    @Test
    public void testfindByType()
    {
    	Type  ty= new Type();
    	ty.setIdty(1L);
    	List<Reservation> res = reservationRepository.findByType(ty);
    	for (Reservation r : res)
    	{
    		System.out.println(r);
    	}
    }
    @Test
    public void findByTypeIdCat()
    {
    	List<Reservation> res = reservationRepository.findByTypeIdty(1L);
    	for (Reservation r : res)
    	{
    		System.out.println(r);
    	}
     }
    @Test
    public void testfindByOrderByNomProduitAsc()
    {
    	List<Reservation> res = reservationRepository.findByOrderByNomclientAsc();
    	for (Reservation r : res)
    	{
    		System.out.println(r);
    	}
    }
    @Test
    public void testTrierReservationsNomsPrix()
    {
    	List<Reservation> res = reservationRepository.trierReservationsNomsPrix();
    	for (Reservation r : res)
    	{
    		System.out.println(r);
    	}
    }



}
