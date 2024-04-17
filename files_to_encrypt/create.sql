CREATE TABLE Tramwaj (
    Nr_tramwaju INT PRIMARY KEY,
    Model VARCHAR(20)
);

CREATE TABLE Kierowca (
    PESEL VARCHAR(11) PRIMARY KEY,
    Imie VARCHAR(15),
    Nazwisko VARCHAR(20),
    Nr_kierowcy INT UNIQUE
);

CREATE TABLE Linia_Tramwajowa (
    Nr_Linii_tramwajowej INT PRIMARY KEY,
	Nr_tramwaju INT FOREIGN KEY REFERENCES Tramwaj(Nr_tramwaju)
);
