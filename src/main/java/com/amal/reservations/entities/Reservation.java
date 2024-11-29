package com.amal.reservations.entities;

import java.util.Date;
import java.util.List;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.OneToMany;
import jakarta.persistence.OneToOne;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
@Data
@AllArgsConstructor

@Entity
public class Reservation {
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private long idReservation;
	private String nomclient;
	private Double prixsejour;
	private Date datedebut;
	private Date datefin;
	@ManyToOne
	private Type type;

	
	public Type getType() {
		return type;
	}

	public void setType(Type type) {
		this.type = type;
	}

	public Reservation() {
		super();
	}
	
	public Reservation(String nomclient, Double prixsejour, Date datedebut, Date datefin) {
		super();
		this.nomclient = nomclient;
		this.prixsejour = prixsejour;
		this.datedebut = datedebut;
		this.datefin = datefin;
	}

	public long getIdReservation() {
		return idReservation;
	}
	public void setIdReservation(long idReservation) {
		this.idReservation = idReservation;
	}
	public String getNomclient() {
		return nomclient;
	}
	public void setNomclient(String nomclient) {
		this.nomclient = nomclient;
	}
	public Double getPrixsejour() {
		return prixsejour;
	}
	public void setPrixsejour(Double prixsejour) {
		this.prixsejour = prixsejour;
	}
	public Date getDatedebut() {
		return datedebut;
	}
	public void setDatedebut(Date datedebut) {
		this.datedebut = datedebut;
	}
	public Date getDatefin() {
		return datefin;
	}
	public void setDatefin(Date datefin) {
		this.datefin = datefin;
	}

	@Override
	public String toString() {
		return "Reservation [idReservation=" + idReservation + ", nomclient=" + nomclient + ", prixsejour=" + prixsejour
				+ ", datedebut=" + datedebut + ", datefin=" + datefin + "]";
	}
	

}
 