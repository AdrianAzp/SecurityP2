package p2;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Date;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.RFC4519Style;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.CertException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.bc.BcRSAContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.bc.BcContentSignerBuilder;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.bc.BcPKCS10CertificationRequestBuilder;
/**
* Esta clase implementa el comportamiento de un usuario en una Infraestructura de Certificación
* @author Seg Red Ser
* @version 1.0
*/
public class Usuario {
	
	private RSAKeyParameters clavePrivada = null;
	private RSAKeyParameters clavePublica = null;

	GestionClaves gc = new GestionClaves();
	GestionObjetosPEM gObj = new GestionObjetosPEM();
	AsymmetricCipherKeyPair parClaves=gc.generarClaves(BigInteger.valueOf(3), 2048);
	private X509CertificateHolder certificadoCA;
	/**
	 * Método que genera y devuelve las claves del usuario.
	 * @param fichClavePrivada: String con el nombre del fichero donde se guardará la clave privada en formato PEM
	 * @param fichClavePublica: String con el nombre del fichero donde se guardará la clave publica en formato PEM
     	 * @throws IOException 	
	 * @return AsymmetricCipherKeyPair: Par de claves del usuario.
	 */
	public AsymmetricCipherKeyPair generarClaves (String fichClavePrivada, String fichClavePublica) throws IOException{
		
		// Esto es nuevo respecto de la P1. Se debe instanciar un objeto de la clase GestionClaves proporcionada
		RSAKeyParameters privadaRSA=(RSAKeyParameters) parClaves.getPrivate();
		RSAKeyParameters publicaRSA=(RSAKeyParameters) parClaves.getPublic();

		byte [] privada = ((gc.getClavePrivadaPKCS8(privadaRSA)).getEncoded());
		byte [] publica = ((gc.getClavePublicaSPKI(publicaRSA)).getEncoded());

		GestionObjetosPEM.escribirObjetoPEM(GestionObjetosPEM.getPkcs8keyPemHeader(),privada, fichClavePrivada);
		GestionObjetosPEM.escribirObjetoPEM("PUBLIC KEY", publica, fichClavePublica);

		return parClaves;		
		
		// Asignar claves a los atributos correspondientes
		// Escribir las claves en un fichero en formatos estándar de clave privada y pública!!

		//IMPLEMENTAR ESTUDIANTE
		
		
    }



	
	/**
	 * Método que genera una petición de certificado en formato PEM,almacenando esta petición en un fichero.
	 * @param parClaves: AsymmetricCipherKeyPair
	 * @param fichPeticion: String con el nombre del fichero donde se guardará la petición de certificado
	 * @throws IOException 
	 * @throws OperatorCreationException 
	 */
	public void crearPetCertificado(String fichPeticion) throws OperatorCreationException, IOException {
		// IMPLEMENTAR POR EL ESTUDIANTE
 
	   	// Configurar hash para resumen y algoritmo firma (MIRAR TRANSPARENCIAS PRESENTACIÓN PRÁCTICA)
		// La solicitud se firma con la clave privada del usuario y se escribe en fichPeticion en formato PEM
		
		PKCS10CertificationRequest peticion = null;
		X500Name nombreUsuario = new X500Name("C=ES, O=DTE, CN=Adrian");

		try {

			peticion = crearPeticionPKCS10(nombreUsuario,
					gc.getClavePublicaMotor(gc.getClavePublicaSPKI(parClaves.getPublic())),
					gc.getClavePrivadaMotor(gc.getClavePrivadaPKCS8(parClaves.getPrivate())));

			GestionObjetosPEM.escribirObjetoPEM(GestionObjetosPEM.PKCS10_PEM_HEADER, peticion.getEncoded(), fichPeticion);

		} catch (Exception e) {
			System.out.println(e.getMessage());
		}
		
		
	}
	
	 /**
		 * Método privado que genera una petición de certificado en formato PKCS10.
		 * @param nombreUsuario: X500Name
		 * @param clavePub: RSAKeyParameters
		 * @param clavePriv: RSAKeyParameters
		 * @return PKCS10CertificationRequest: Petición de certificación en formato PKCS10.
		 * @throws OperatorCreationException 
		 * @throws IOException 
		 */
		private PKCS10CertificationRequest crearPeticionPKCS10(X500Name nombreUsuario, RSAKeyParameters clavePub, RSAKeyParameters clavePriv) throws OperatorCreationException, IOException {
			  
			PKCS10CertificationRequest pet=null;
			PKCS10CertificationRequestBuilder requestBuilder=new BcPKCS10CertificationRequestBuilder(nombreUsuario,clavePub);
			DefaultSignatureAlgorithmIdentifierFinder sigAF = new DefaultSignatureAlgorithmIdentifierFinder();//identificador del algoritmo de la firma
			DefaultDigestAlgorithmIdentifierFinder digAF = new DefaultDigestAlgorithmIdentifierFinder();//firma creada   
			AlgorithmIdentifier sigAI = sigAF.find("SHA256withRSA");
			AlgorithmIdentifier digAI = digAF.find(sigAI);
			BcContentSignerBuilder csb=new BcRSAContentSignerBuilder(sigAI, digAI);
			pet=requestBuilder.build(csb.build(clavePriv));
			return pet;
		}
	/**
	 * Método que verifica un certificado de una entidad.
	 * @param fichCertificadoCA: String con el nombre del fichero donde se encuentra el certificado de la CA
	 * @param fichCertificadoUsu: String con el nombre del fichero donde se encuentra el certificado de la entidad
     * @throws CertException 
	 * @throws OperatorCreationException 
	 * @throws IOException 
	 * @throws FileNotFoundException 	
	 * @return boolean: true si verificación OK, false en caso contrario.
	 */
    public boolean verificarCertificadoExterno(String fichCertificadoCA, String fichCertificadoUsu)throws OperatorCreationException, CertException, FileNotFoundException, IOException {
    	// IMPLEMENTAR POR EL ESTUDIANTE
	// Comprobar fecha validez del certificado
	// Si la fecha es válida, se comprueba la firma
	// Generar un contenedor para la verificación, con la clave pública de CA.
    	
    	boolean verificado=false;
    	
    	X509CertificateHolder certificadoCA = null;
		X509CertificateHolder certificadoUsu = null;		
		
		certificadoCA = (X509CertificateHolder) GestionObjetosPEM.leerObjetoPEM(fichCertificadoCA);
		certificadoUsu = (X509CertificateHolder) GestionObjetosPEM.leerObjetoPEM(fichCertificadoUsu);
		//System.out.println("LLego aqui 2");
		//comprobamos la fecha de validez es posterioir a la emision y anterior a la caducidad
		Date fechaActual = new Date(System.currentTimeMillis());
		Date fechaInicio = certificadoUsu.getNotBefore();
		Date fechaFin = certificadoUsu.getNotAfter();
		if(!fechaActual.before(fechaInicio) && !fechaActual.after(fechaFin))
			verificado=this.verificarFirmaCertificado(certificadoUsu, certificadoCA);
		System.out.println("LLego aqui 3");
		return verificado;
    	
    	
    	/*boolean verificado=false;
		DefaultDigestAlgorithmIdentifierFinder digAF = new DefaultDigestAlgorithmIdentifierFinder();//firma creada   

    	certificadoCA = null;
		
    	X509CertificateHolder certUsuario = (X509CertificateHolder) GestionObjetosPEM.leerObjetoPEM(fichCertificadoUsu);
		Date fechaActual = new Date(System.currentTimeMillis());
		Date fechaInicio = certUsuario.getNotBefore();
		Date fechaFin = certUsuario.getNotAfter();
		if(!fechaActual.before(fechaInicio) && !fechaActual.after(fechaFin))
			certificadoCA = (X509CertificateHolder) GestionObjetosPEM.leerObjetoPEM(fichCertificadoCA);
			gc.getClavePublicaSPKI(clavePublica);
			ContentVerifierProvider content = new BcRSAContentVerifierProviderBuilder(digAF).build(clavePublica);
			if(certUsuario.isSignatureValid(content))
			{verificado=true;}
		return verificado;*/
	}	
   

	/**
	 * Método privado que verifica la firma de un certificado de entidad.
	 * @param certificadoEntidad: X509CertificateHolder 
	 * @param certificadoCA: X509CertificateHolder 
	 * @return boolean: true si verificación OK, false en caso contrario.
	 * @throws CertException 
	 * @throws OperatorCreationException 
	 * @throws IOException 
	 */
	private boolean verificarFirmaCertificado (X509CertificateHolder certificadoEntidad, X509CertificateHolder certificadoCA) throws CertException, OperatorCreationException, IOException {
		
		boolean verificado=false;

		DefaultDigestAlgorithmIdentifierFinder defDigAIF = new DefaultDigestAlgorithmIdentifierFinder();
		SubjectPublicKeyInfo publica = certificadoCA.getSubjectPublicKeyInfo();
		RSAKeyParameters publicKeyCA = gc.getClavePublicaMotor(publica);
		ContentVerifierProvider contentVerifierProvider = new BcRSAContentVerifierProviderBuilder(defDigAIF).build(publicKeyCA);
		if(certificadoEntidad.isSignatureValid(contentVerifierProvider))
			verificado=true;
		
		return verificado;
	}
}

	// EL ESTUDIANTE PODRÁ CODIFICAR TANTOS MÉTODOS PRIVADOS COMO CONSIDERE INTERESANTE PARA UNA MEJOR ORGANIZACIÓN DEL CÓDIGO