package p2;

import java.util.Calendar;
import java.util.GregorianCalendar;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import java.security.spec.InvalidKeySpecException;
import java.util.Date;
import java.util.Scanner;


public class Principal {
	
	public static void main(String[] args) throws Exception {

		Usuario u =new Usuario();
		CA ca=new CA();
		
		int menu1;
		int menu2;
		Scanner sc = new Scanner(System.in);
		String fichero;
		
		//Para trabajo como usuario
		String ficheroClavePrivada;
		String ficheroClavePublica;
		
		// Clase para el par de claves
		AsymmetricCipherKeyPair parClavesUsu=null;  
		
		//Para trabajo como CA
		AsymmetricCipherKeyPair parClavesCA = null;
		String ficheroCA=null;
		String ficheroCertUsu=null;
		
		do {
			// Ejemplo de calendario. 
			// Sólo para ver tiempo actual, cuál sería la fecha inicio certificado 
			// y la de fin certificado
			// Date fecha=new Date(System.currentTimeMillis());
			// System.out.println("Fecha actual...:"+fecha.toString()); // Momento actual
			
			//Calendar c1 = GregorianCalendar.getInstance();
			//Date fechaInicioCert=c1.getTime(); 
			//Devuelve la Date actual. Mismo valor que fecha
			//System.out.println("Fecha Inicio Certificado: "+fechaInicioCert.toString());
			
			//c1.add(Calendar.YEAR, 4); //añadir 4 años al calendario Para la CA.
		    	//Date fechaFinCert=c1.getTime(); 
			// cuatro años a partir del momento actual. 
			//System.out.println("fecha Fin Certificado :"+fechaFinCert.toString());
			
			System.out.println("\nFECHAS");
			Date fecha = new Date(System.currentTimeMillis());
			System.out.println("Fecha actual...:" + fecha.toString());

			Date fechaInicioCert = GregorianCalendar.getInstance().getTime();
			System.out.println("FechaInicioCert...:" + fechaInicioCert.toString());

			Calendar c1 = GregorianCalendar.getInstance();
			c1.add(Calendar.YEAR, 4);
			Date fechaFinCert = c1.getTime();
			System.out.println("fechaFinCert...:" + fechaFinCert.toString() + "\n\n");

		  	System.out.println("¿Con qué rol desea trabajar?");
			System.out.println("1. Trabajar como usuario.");
			System.out.println("2. Trabajar como Autoridad de Certificación.");
			System.out.println("3. Salir.");
			menu1 = sc.nextInt();
		
			switch(menu1){
				case 1:
					do{
						System.out.println("Elija una opción para trabajar como USUARIO:");
						System.out.println("0. Volver al menú anterior.");
						System.out.println("1. Generar pareja de claves en formato PEM.");
						System.out.println("2. Crear petición de certificación.");
						System.out.println("3. Verificar certificado externo.");
						menu2 = sc.nextInt();
				
						switch(menu2){
							case 1://Generar pareja de claves.
								System.out.println("OPCIÓN GENERA PAREJA DE CLAVES");
								System.out.println("Escriba el nombre del fichero que contendrá la clave privada:");
								ficheroClavePrivada = sc.next();
								System.out.println("Escriba el nombre del fichero que contendrá la clave publica:");
								ficheroClavePublica = sc.next();
								parClavesUsu = u.generarClaves(ficheroClavePrivada, ficheroClavePublica);
								// COMPLETAR ESTUDIANTE
								
								
							break;
							case 2://Crear petición de certificado.
								if (parClavesUsu==null)
									System.out.println("El usuario debe tener un par de claves");
								else
								{
									System.out.println("Escriba el nombre del fichero que contendrá la petición de certificación:");
									fichero= sc.next();
									u.crearPetCertificado( fichero);
									//COMPLETAR ESTUDIANTE
								
							    	}
								
							break;
							case 3://Verificar certificado externo.
								if (parClavesUsu == null)
									System.out.println("\nEl usuario debe tener un par de claves");
								else {
							    	System.out.println("Escriba el nombre del fichero que contiene el certificado del usuario:");
								fichero = sc.next();
							    	System.out.println("Escriba el nombre del fichero que contiene el certificado de la CA:");
								ficheroCA = sc.next();
								if(u.verificarCertificadoExterno(ficheroCA, fichero))
									System.out.println("El certificado esta correcto");
								else
									System.out.println("Certificado inválido");
								}
								//COMPLETAR ESTUDIANTE  
				        
							break;
						}
					} while(menu2 != 0);
				break;
				case 2:
					do{
						System.out.println("Elija una opción para trabajar como CA:");
						System.out.println("0. Volver al menú anterior.");
						System.out.println("1. Generar pareja de claves y el certificado autofirmado.");
						System.out.println("2. Cargar pareja de claves.");
						System.out.println("3. Generar un certificado a partir de una petición.");
						menu2 = sc.nextInt();
						switch(menu2){
							case 1://Generar pareja de claves, el certificado X509 y guardar en ficheros.
								ca.inicializar(false);
								System.out.println("Claves y certificados X509 GENERADOS");
								System.out.println("Se han guardado en " + CA.NOMBRE_FICHERO_CRT + ", " + CA.NOMBRE_FICHERO_CLAVES + "-*.txt");									
							break;
							case 2://Cargar de fichero pareja de claves
								ca.inicializar(true);
								System.out.println("Claves CARGADAS");
								System.out.println("Se han cargado de " + CA.NOMBRE_FICHERO_CLAVES + "-*.txt");								
								
							break;
							case 3:// Generar certificado a partir de una petición
								    System.out.println("Escriba el nombre del fichero que contiene la petición de certificación del usuario:");
								    fichero = sc.next();
									System.out.println("Escriba el nombre del fichero que contendrá el certificado emitido por la CA para el usuario:");
								    ficheroCertUsu = sc.next();
										if(ca.certificarPeticion(fichero, ficheroCertUsu))
											System.out.println("Certificado generado correctamente a partir de la petición");
										else
											System.out.println("Petición inválida");
									
								    // A COMPLETAR ESTUDIANTE
								    
								    
							break;							
						}
					} while(menu2 != 0);
				break;
			}				} while(menu1 != 3);
     
		sc.close();         
	}	
}

