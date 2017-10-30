# secpass

This software attempts to be a secure, but memorable, password generator. Although new and experimental, plenty of features and improvements are planned.

It employs a simple markov chain algorithm to produce pronounceable sequences of letters (or pseudowords). The markov chain records first and second-order state transition frequency distributions from an input wordlist, which means that letters depend on up to two previous letters.

 Additionally, password strength can be precisely specified by a desired number of bits of entropy, and everything else, such as length, is determined automatically.

Being an experimental demo, I would not recommend actually using any passwords generated from this at this time for anything important.

Depends on [libsodium](https://github.com/jedisct1/libsodium) and currently only Linux is officially supported, as it relies on the [getrandom](http://man7.org/linux/man-pages/man2/getrandom.2.html) system call for secure randomness. Other platforms will likely be supported as secpass matures.

Below are some sample passwords using [this wordlist](https://github.com/dwyl/english-words/blob/master/words_alpha.txt) as input:

    30-bits minimum entropy:
        (length: 10, bits: 34)	Reds~Xamsn
        (length: 7, bits: 31)	4XlWave
        (length: 8, bits: 31)	YoOhnshe
        (length: 10, bits: 30)	Quers$Mate
        (length: 8, bits: 34)	$Jaymed;
        (length: 7, bits: 32)	Rankrd5
        (length: 7, bits: 32)	Kise|Km
        (length: 7, bits: 33)	RipSal&
        (length: 9, bits: 33)	$InsiveDi
        (length: 7, bits: 31)	=Hanet4
    40-bits minimum entropy:
        (length: 10, bits: 40)	ZedhodUpts
        (length: 11, bits: 40)	3RefulJobs$
        (length: 10, bits: 44)	HuaQu^Unnv
        (length: 10, bits: 44)	Me(Red>Re.
        (length: 10, bits: 43)	0TeAticDe0
        (length: 9, bits: 40)	Ter<Fris/
        (length: 12, bits: 43)	Nersus^Venda
        (length: 12, bits: 44)	TviesHinted1
        (length: 9, bits: 41)	2To'Mary.
        (length: 9, bits: 42)	Sh=Kagun]
    50-bits minimum entropy:
        (length: 12, bits: 53)	FuDonece"Can
        (length: 11, bits: 52)	$Diatip+Ce,
        (length: 12, bits: 53)	1JdsmWinine6
        (length: 13, bits: 52)	3SuYanYoYeds?
        (length: 12, bits: 50)	'Insing<Usr=
        (length: 12, bits: 50)	|XembioGron-
        (length: 12, bits: 51)	,Vers@Sibie=
        (length: 12, bits: 52)	Ing8GuryGby+
        (length: 12, bits: 54)	#Ci2AcharOft
        (length: 12, bits: 52)	:Vi_JactPon3
    60-bits minimum entropy:
        (length: 14, bits: 64)	EgamsFills=Sk8
        (length: 16, bits: 63)	#Dism#DepticPeDe
        (length: 17, bits: 62)	-SonsTedGovasNals
        (length: 14, bits: 60)	.Na!Tery!Adsly
        (length: 15, bits: 60)	-Ents#Ke?Ellym6
        (length: 14, bits: 60)	JeatFalyGattu|
        (length: 15, bits: 64)	Ded;UsieQa:Yots
        (length: 14, bits: 60)	Zo.Cl5CongerSh
        (length: 17, bits: 63)	/Gual8Quare^Xamor
        (length: 16, bits: 61)	1KentedLictCiOrm
    70-bits minimum entropy:
        (length: 18, bits: 73)	#Wi?ProseLioYoutHo
        (length: 15, bits: 74)	Ko%Wit*YiOgers>
        (length: 20, bits: 72)	!ThsRepuba_ChiZukets
        (length: 21, bits: 70)	NonsonXedsFixes1Zons<
        (length: 17, bits: 73)	Norag$PlWoRempts<
        (length: 20, bits: 71)  Pants@AricZateda@Gly
        (length: 17, bits: 72)	3Alify3Kettm:Bage
        (length: 19, bits: 74)	GintesJudg@AmCrect1
        (length: 20, bits: 70)	GconeQuityTolds%Nome
        (length: 15, bits: 71)	'Youk6BuntZeFa2
