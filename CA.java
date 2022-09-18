package p2;

import java.util.Calendar;
import java.util.GregorianCalendar;
import java.io.IOException;
import java.math.BigInteger;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCSException;
import java.util.Date;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcContentSignerBuilder;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.bouncycastle.operator.bc.BcRSAContentVerifierProviderBuilder;

/**
* Esta clase implementa el comportamiento de una CA
* @author Seg Red Ser
* @version 1.0
*/
public class CA {
	
	private final X500Name nombreEmisor;
	private BigInteger numSerie;
	private final int añosValidez; 
	
	public final static String NOMBRE_FICHERO_CRT = "CertificadoCA.crt";
	public final static String NOMBRE_FICHERO_CLAVES = "CA-clave";
	
	private RSAKeyParameters clavePrivadaCA = null;
	private RSAKeyParameters clavePublicaCA = null;
	
	GestionClaves gc = new GestionClaves();
	GestionObjetosPEM gObj = new GestionObjetosPEM();
	/**
	 * Constructor de la CA. 
	 * Inicializa atributos de la CA a valores por defecto
	 */
	public CA () {
		// Distinguished Name DN. C Country, O Organization name, CN Common Name. 
		this.nombreEmisor = new X500Name ("C=ES, O=DTE, CN=CA");
		this.numSerie = BigInteger.valueOf(1);
		this.añosValidez = 1; // Son los años de validez del certificado de usuario, para la CA el valor es 4
	}
	/**
	 * Constructor de la CA. 
	 * @param numSerie: entero con el número de serie que será utilizado para crear el certificado de la CA 
	 */
	public CA (int numSerie) {
		
		this.nombreEmisor = new X500Name ("C=ES, O=DTE, CN=CA");
		this.numSerie = BigInteger.valueOf(numSerie);
		this.añosValidez = 1;
	}
	/**
	 * Método que comprueba si ya se han generado las claves de la CA
	 * @return boolean: true si ya se habían generado, false en otro caso.
	 */
	private boolean hayClavesCA (){
		
		boolean clavesGen=false;
		
		if((clavePrivadaCA!=null) && (clavePublicaCA!=null))
			clavesGen=true;			
		
		return clavesGen;		
	}

	
	 /**
	 * Método que inicializa la CA. Carga la parejas de claves de la CA o genera la parejas de claves de la CA y el certificado 
         * autofirmado de la CA.
	 * @param cargar:boolean. Si es true, carga las claves de ficheros existentes. Si es false, genera datos nuevos y los guarda en 
         * ficheros para su uso posterior. 
	 * @throws OperatorCreationException
	 * @throws IOException 
	 */
	
	public void inicializar (boolean cargar) throws OperatorCreationException, IOException{
		
		//COMPLETAR POR EL ESTUDIANTE

		if (cargar) {
			cargarClaves();	
		}
			// Ha entrado aquí porque los ficheros con las claves y el certificado ya estaban generados
                        // Carga la pareja de claves de los ficheros indicados por NOMBRE_FICHERO_CLAVES 
                        // (añadiendo al nombre las cadenas "_pri.txt" y "_pu.txt"
			//COMPLETAR POR EL ESTUDIANTE
		
		else {
			guardarClaves();
			// Generar una pareja de claves y guardarla en los ficheros indicados por NOMBRE_FICHERO_CLAVES 
                        // (añadiendo al nombre las cadenas "_pri.txt" y "_pu.txt"
			// Generar un certificado autofirmado: 
			// 	1. Configurar parámetros para el certificado
			// 	2. Configurar hash para resumen y algoritmo firma (MIRAR TRANSPARENCIAS DE APOYO EN MOODLE)
			//	3. Generar certificado
			//	4. Guardar el certificado en formato PEM como un fichero con extensión crt (NOMBRE_FICHERO_CRT)
		
		}
		Calendar finCer = GregorianCalendar.getInstance();
		finCer.add(Calendar.YEAR,4);
		Date fFCer=finCer.getTime();

		if(!hayClavesCA()){
			System.exit(0);
		}
		
		X509v3CertificateBuilder certificado = new X509v3CertificateBuilder (nombreEmisor, numSerie, new Date(System.currentTimeMillis()), fFCer, nombreEmisor, gc.getClavePublicaSPKI(clavePublicaCA));

		DefaultSignatureAlgorithmIdentifierFinder sigAF = new DefaultSignatureAlgorithmIdentifierFinder();//firma
		DefaultDigestAlgorithmIdentifierFinder digAF = new DefaultDigestAlgorithmIdentifierFinder();//firma

		AlgorithmIdentifier sigAI = sigAF.find("SHA256withRSA");
		AlgorithmIdentifier digAI = digAF.find(sigAI);

		BcContentSignerBuilder csb=new BcRSAContentSignerBuilder(sigAI, digAI);

		//Construimos el certificado usando la firma con la clave privada de la CA
		X509CertificateHolder cerHolder=certificado.build(csb.build(clavePrivadaCA));//generar y guardar el certificado

		//Guardamos el holder como objeto PEM
		GestionObjetosPEM.escribirObjetoPEM("CERTIFICATE", cerHolder.getEncoded(),NOMBRE_FICHERO_CRT );
	}
	/**
	 * Método para cargar las claves
	 * @throws IOException
	 */
	private void cargarClaves() throws IOException{
		
		GestionClaves gestionClaves = new GestionClaves();
		clavePublicaCA = gestionClaves.getClavePublicaMotor((SubjectPublicKeyInfo)GestionObjetosPEM.leerObjetoPEM(NOMBRE_FICHERO_CLAVES+"-public"));
		clavePrivadaCA = gestionClaves.getClavePrivadaMotor((PrivateKeyInfo)GestionObjetosPEM.leerObjetoPEM(NOMBRE_FICHERO_CLAVES+"-private"));

		
	}
	/**
	 * Metodo para guardar las claves
	 * @throws IOException
	 */
	private void guardarClaves() throws IOException{
		
		//GestionObjetosPEM gestionObjetosPEM = new GestionObjetosPEM();
		GestionClaves gestionClaves = new GestionClaves();
		AsymmetricCipherKeyPair parClaves=gc.generarClaves(BigInteger.valueOf(3), 2048);

		//FORMATO PEM
		GestionObjetosPEM.escribirObjetoPEM(GestionObjetosPEM.PUBLICKEY_PEM_HEADER, gestionClaves.getClavePublicaSPKI(parClaves.getPublic()).getEncoded(), NOMBRE_FICHERO_CLAVES+"-public");
		GestionObjetosPEM.escribirObjetoPEM(GestionObjetosPEM.getPkcs8keyPemHeader(), gestionClaves.getClavePrivadaPKCS8(parClaves.getPrivate()).getEncoded(), NOMBRE_FICHERO_CLAVES+"-private");
		
		clavePrivadaCA = (RSAKeyParameters) parClaves.getPrivate();
		clavePublicaCA = (RSAKeyParameters) parClaves.getPublic();

		
	}
	/**
	 * Método que genera el certificado de un usuario a partir de una petición de certificación
	 * @param ficheroPeticion:String. Parámetro con la petición de certificación
	 * @param ficheroCertUsu:String. Parámetro con el nombre del fichero en el que se guardará el certificado del usuario
	 * @throws IOException 
	 * @throws PKCSException 
	 * @throws OperatorCreationException
	 */
	public boolean certificarPeticion(String ficheroPeticion, String ficheroCertUsu) throws IOException, 
	OperatorCreationException, PKCSException{
		
		//  Se comprueba firma del solicitante: Descifrar firma con la clave pública solicitante y 
		//  verificar que es igual al resumen generado 
		//  Se genera el certificado firmado con la clave privada de la CA
		//  Se guarda el certificado en formato PEM como un fichero con extensión crt

		boolean certificar=false;
		PKCS10CertificationRequest peticion=(PKCS10CertificationRequest) GestionObjetosPEM.leerObjetoPEM(ficheroPeticion);		
		
		//configuro el contenedor
		X509CertificateHolder certificado = this.crearCertificado(peticion);
		if(certificado.isValidOn(new Date(System.currentTimeMillis()))) {
			certificar=true;
		}
			//guardar certificado en formato PEM
			GestionObjetosPEM.escribirObjetoPEM("CERTIFICATE", certificado.getEncoded(), ficheroCertUsu);
	 return certificar;
	}
	/**
	 * Método privado que comprueba la validez de la firma de una petición de certificación.
	 * Esta verificación es necesaria llevarla a cabo para crear el Certificado de usuario a partir de la petición de certificación
	 * @param pet:PKCS10CertificationRequest. Parámetro con la petición de certificación en formato PKCS10
	 * @param clavePub:RSAKeyParameters. Parámetro con la clave pública
	 * @return boolean: true si verificación firma OK, false en caso contrario.
	 * @throws PKCSException 
	 * @throws OperatorCreationException 
	 */	
	private boolean verificaFirmaDePeticion (PKCS10CertificationRequest pet, RSAKeyParameters clavePub) throws OperatorCreationException, PKCSException {
		
		boolean verificado=false;
		DefaultDigestAlgorithmIdentifierFinder digAF = new DefaultDigestAlgorithmIdentifierFinder();
		if(pet.isSignatureValid(new BcRSAContentVerifierProviderBuilder(digAF).build(clavePub)))
			verificado=true;
	
		return verificado;
	}
	/**
	 * Método que genera el certificado autofirmado de la CA
	 * @param parClavesCA:AsymmetricCipherKeyPair. Parámetro con el par de claves de la CA
	 * @param fichCertificadoCA:String. Parámetro con el nombre del fichero en el que se guardará el certificado de la CA
	 * @throws IOException 
	 * @throws OperatorCreationException 
	 */
	public void crearCertificadoAutofirmado(AsymmetricCipherKeyPair parClavesCA, String fichCertificadoCA) throws IOException, OperatorCreationException {

		Calendar finCer = GregorianCalendar.getInstance();
		finCer.add(Calendar.YEAR,4);
		Date fFCer=finCer.getTime();

		if(!hayClavesCA()){
			System.exit(0);
		}
		X509v3CertificateBuilder certificado = new X509v3CertificateBuilder (nombreEmisor, numSerie, new Date(System.currentTimeMillis()), fFCer, nombreEmisor, gc.getClavePublicaSPKI(clavePublicaCA));

		DefaultSignatureAlgorithmIdentifierFinder sigAF = new DefaultSignatureAlgorithmIdentifierFinder();
		DefaultDigestAlgorithmIdentifierFinder digAF = new DefaultDigestAlgorithmIdentifierFinder();

		AlgorithmIdentifier sigAI = sigAF.find("SHA256withRSA");
		AlgorithmIdentifier digAI = digAF.find(sigAI);

		BcContentSignerBuilder csb =new BcRSAContentSignerBuilder(sigAI, digAI);

		//Construimos el certificado usando la firma con la clave privada de la CA
		X509CertificateHolder cerHolder=certificado.build(csb.build(clavePrivadaCA));;

		//Guardamos el holder como objeto PEM
		GestionObjetosPEM.escribirObjetoPEM("CERTIFICATE", cerHolder.getEncoded(), fichCertificadoCA);
	}
	/**
	 * Método privado que genera el certificado de un usuario a partir de una petición de certificación
	 * Este método es necesario emplearlo para Certificar una Petición
	 * @param pet:PKCS10CertificationRequest. Parámetro con la petición de certificación en formato PKCS10
	 * @throws PKCSException 
	 * @throws OperatorCreationException 
	 * @throws IOException 
	 * @result X509CertificateHolder: certificado X.509
	 */
	private X509CertificateHolder crearCertificado (PKCS10CertificationRequest pet) throws OperatorCreationException, PKCSException, IOException {
	
		X509CertificateHolder cerHolder=null;
		
		//Obtenemos la clave publica de la entidad solicitante
		SubjectPublicKeyInfo clavePubES = pet.getSubjectPublicKeyInfo();
		RSAKeyParameters clavePubEntidad = gc.getClavePublicaMotor(clavePubES);

		if(this.verificaFirmaDePeticion(pet,clavePubEntidad)){
			
			X500Name nombreSolicitante = pet.getSubject();

			Calendar finCer = GregorianCalendar.getInstance();
			finCer.add(Calendar.YEAR, añosValidez);
			Date fFCer=finCer.getTime();

			X509v3CertificateBuilder certBldr = new X509v3CertificateBuilder(nombreEmisor, numSerie, new Date(System.currentTimeMillis()), fFCer, nombreSolicitante, clavePubES);

			DefaultSignatureAlgorithmIdentifierFinder sigAF = new DefaultSignatureAlgorithmIdentifierFinder();
			DefaultDigestAlgorithmIdentifierFinder digAF = new DefaultDigestAlgorithmIdentifierFinder();

			AlgorithmIdentifier sigAI = sigAF.find("SHA256withRSA");
			AlgorithmIdentifier digAI = digAF.find(sigAI);

			BcContentSignerBuilder csBuilder= new BcRSAContentSignerBuilder(sigAI, digAI);

			cerHolder = certBldr.build(csBuilder.build(this.clavePrivadaCA));
		}
		
		return cerHolder;
	}
}	

	// EL ESTUDIANTE PODRÁ CODIFICAR TANTOS MÉTODOS PRIVADOS COMO CONSIDERE INTERESANTE PARA UNA MEJOR ORGANIZACIÓN DEL CÓDIGO