# secpass

This software attempts to be a secure, but memorable, password generator. Although new and experimental, plenty of features and improvements are planned.

It employs a simple markov chain algorithm to produce pronounceable sequences of letters (or pseudowords). The markov chain records first and second-order state transition frequency distributions from an input wordlist, which means that letters depend on up to two previous letters.

 Additionally, password strength can be precisely specified by a desired number of bits of entropy, and everything else, such as length, is determined automatically.

Being an experimental demo, I would not recommend actually using any passwords generated from this at this time for anything important.

Depends on [libsodium](https://github.com/jedisct1/libsodium) for cryptographic randomness and secure handling of sensitive memory.

Below are some sample passwords using [this wordlist](https://github.com/dwyl/english-words/blob/master/words_alpha.txt) as input:

    30-bits minimum entropy:
        (length: 8, bits: 32)	8VelyRe#
        (length: 7, bits: 30)	Dus[Tic
        (length: 7, bits: 31)	LoneMi"
        (length: 8, bits: 32)	#Touses6
        (length: 7, bits: 33)	1He4Jos
        (length: 9, bits: 30)	EntPereee
        (length: 6, bits: 30)	.Ruds,
        (length: 10, bits: 34)	XtLiticsNo
        (length: 8, bits: 33)	~Her-Der
        (length: 6, bits: 31)	8Zlon"
    40-bits minimum entropy:
        (length: 12, bits: 41)	;TrogyPodism
        (length: 9, bits: 41)	1OvyBerOt
        (length: 13, bits: 43)	Coityl,Dessis
        (length: 11, bits: 42)	Denese%Ent;
        (length: 9, bits: 43)	7OgyShon2
        (length: 8, bits: 44)	IlSrhOv?
        (length: 10, bits: 42)	4SwoodsTr2
        (length: 12, bits: 42)	@SloseOvers*
        (length: 11, bits: 40)	Cid{Quited.
        (length: 11, bits: 44)	BronsLozos7
    50-bits minimum entropy:
        (length: 13, bits: 53)	@Vor_UnosisOc
        (length: 11, bits: 50)	Xis~Rim,Nic
        (length: 14, bits: 50)	_YoticsColity0
        (length: 11, bits: 50)	SnChuchLed+
        (length: 14, bits: 54)	Ths3CuliHtiner
        (length: 15, bits: 52)	-ZoodWillysGums
        (length: 12, bits: 50)	#Lus%Menids,
        (length: 14, bits: 51)	~WynonsFolows;
        (length: 13, bits: 54)	Bruse^XoInon/
        (length: 14, bits: 50)	RedomWishXyomy
    60-bits minimum entropy:
        (length: 14, bits: 60)	/CylVinVessno~
        (length: 18, bits: 64)	?IterikPersRettic_
        (length: 16, bits: 60)	BedHerQueNe5Ove*
        (length: 14, bits: 61)	3Howein&WriKos
        (length: 15, bits: 62)	&Quot*Zi3Unwrin
        (length: 14, bits: 62)	}PidLlenor6Xic
        (length: 14, bits: 62)	Fa4XyuperOv{Bu
        (length: 15, bits: 63)	YkGrimErysLogyn
        (length: 14, bits: 62)	-JotUn*LessVe+
        (length: 13, bits: 61)	:Ta5Enwoof0No
    70-bits minimum entropy:
        (length: 17, bits: 73)	?Pprt1NedlykGion8
        (length: 15, bits: 71)	}HuKe)Lier-Jun$
        (length: 16, bits: 71)	XolusoEtorZishy6
        (length: 21, bits: 73)	InelyIlow+KullyWhetry
        (length: 16, bits: 74)	)Di\Eety/NolQuEl
        (length: 19, bits: 73)	YedTizesZun$Unwing[
        (length: 18, bits: 70)	$InecidUnne,Glouso
        (length: 18, bits: 70)	2De;EptRetersHome}
        (length: 15, bits: 73)	Tyn8XeLecousDw.
        (length: 19, bits: 74)	\ZomePhoeFr"ReQuist
