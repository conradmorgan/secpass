# secpass

This software attempts to be a secure, but memorable, password generator. Although new and experimental, plenty of features and improvements are planned.

It employs a simple markov chain algorithm to produce pronounceable sequences of letters (or pseudowords). The markov chain records first and second-order state transition frequency distributions from an input wordlist, which means that letters depend on up to two previous letters.

 Additionally, password strength can be precisely specified by a desired number of bits of entropy, and everything else, such as length, is determined automatically.

Being an experimental demo, I would not recommend actually using any passwords generated from this at this time for anything important.

Depends on [libsodium](https://github.com/jedisct1/libsodium) and currently only Linux is officially supported, as it relies on the [getrandom](http://man7.org/linux/man-pages/man2/getrandom.2.html) system call for secure randomness. Other platforms will likely be supported as secpass matures.

Below are some sample passwords using [this wordlist](https://github.com/dwyl/english-words/blob/master/words_alpha.txt) as input:

    30-bits minimum entropy:
        (length: 8, bits: 31)	JeckOck[
        (length: 6, bits: 31)	#Ecst!
        (length: 7, bits: 31)	Btisly@
        (length: 7, bits: 32)	!WigUn^
        (length: 6, bits: 33)	4YrIm@
        (length: 7, bits: 31)	Red(Eft
        (length: 7, bits: 30)	Sess9Sc
        (length: 7, bits: 32)	6Medie?
        (length: 8, bits: 31)	7Cresse-
        (length: 6, bits: 32)	Bo>Xn6
    40-bits minimum entropy:
        (length: 9, bits: 40)	Rtedy#Ho0
        (length: 11, bits: 43)	OrphJaMtedy
        (length: 9, bits: 43)	7Yns?UnMt
        (length: 8, bits: 41)	BeychMt,
        (length: 9, bits: 40)	LmosorBr-
        (length: 12, bits: 42)	Fctic6Hblety
        (length: 9, bits: 40)	XaPhilos6
        (length: 10, bits: 42)	LteSc^Ove=
        (length: 12, bits: 43)	WrdsyWrment!
        (length: 12, bits: 44)	0TionsSties;
    50-bits minimum entropy:
        (length: 12, bits: 51)	3HomyVirPess
        (length: 12, bits: 54)	0TteEncopQu;
        (length: 11, bits: 51)	StrusOu$Bu&
        (length: 13, bits: 52)	QuinVe[Zlist.
        (length: 11, bits: 50)	<Ito&Jurses
        (length: 12, bits: 52)	=Gu(Ding\Rte
        (length: 12, bits: 50)	Bungsp^Voles
        (length: 15, bits: 52)	Ovents$BisHnest
        (length: 12, bits: 52)	VaMrtide=Krd
        (length: 11, bits: 53)	VssSt+Fo]In
    60-bits minimum entropy:
        (length: 14, bits: 60)	3XnGsideLceold
        (length: 16, bits: 62)	+CronHip#Vlessl.
        (length: 13, bits: 64)	;Qa]HblyteWh+
        (length: 15, bits: 60)	Stry$ExismErid;
        (length: 15, bits: 63)	ZnzyNbersUnvol1
        (length: 14, bits: 64)	-Rvics_WyesDix
        (length: 15, bits: 63)	Xmoses(WtedrsEx
        (length: 20, bits: 62)	OverOusBoryQueYnting
        (length: 14, bits: 61)	UrnSce5ItersLg
        (length: 15, bits: 62)	TteriElylZmondo
    70-bits minimum entropy:
        (length: 16, bits: 72)	?XhyIn+Ca@Unted8
        (length: 18, bits: 72)	Grchip0Jism3Nters#
        (length: 19, bits: 73)	DelefyGusselOverys<
        (length: 16, bits: 70)	0BlerHwk2OushMty
        (length: 17, bits: 73)	Mic;JingsJin)Ygi^
        (length: 17, bits: 70)	!Vive$Lnted2Yope&
        (length: 16, bits: 71)	}Vg!VermsyKinin(
        (length: 18, bits: 73)	Quidom$Wrric8Wr_Cl
        (length: 17, bits: 72)	2Wtent=OuingeKrd-
        (length: 19, bits: 74)	XntsTswedYmXeKellys
