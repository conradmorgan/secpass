# secpass

This software attempts to be a secure, but memorable, password generator. Although new and experimental, plenty of features and improvements are planned.

It employs a simple markov chain algorithm to produce pronounceable sequences of letters (or pseudowords). The markov chain records first and second-order state transition frequency distributions from an input wordlist, which means that letters depend on up to two previous letters.

 Additionally, password strength can be precisely specified by a desired number of bits of entropy, and everything else, such as length, is determined automatically.

Being an experimental demo, I would not recommend actually using any passwords generated from this at this time for anything important.

Depends on [libsodium](https://github.com/jedisct1/libsodium) for cryptographic randomness and secure handling of sensitive memory.

Below are some sample passwords using [this wordlist](https://github.com/dwyl/english-words/blob/master/words_alpha.txt) as input:

    30-bits minimum entropy:
        (length: 6, bits: 31)	#Ceri<
        (length: 7, bits: 34)	!JyFole
        (length: 8, bits: 34)	JaMetsBt
        (length: 8, bits: 34)	&MistIn;
        (length: 9, bits: 34)	QueOuPre}
        (length: 6, bits: 34)	4Bu+Pl
        (length: 9, bits: 34)	<QueXled%
        (length: 7, bits: 32)	!Hynce_
        (length: 7, bits: 34)	XaTlyp]
        (length: 6, bits: 33)	1Ca0Et
    40-bits minimum entropy:
        (length: 9, bits: 42)	Flcle"Ses
        (length: 8, bits: 42)	5We^Orgs
        (length: 9, bits: 42)	[LtLtyUde
        (length: 10, bits: 42)	^GtessKit5
        (length: 9, bits: 40)	<BckBood;
        (length: 10, bits: 40)	5JibbicFce
        (length: 11, bits: 43)	>UpertsEnth
        (length: 10, bits: 42)	2Tlity-Qu}
        (length: 12, bits: 43)	5QuileXinomy
        (length: 11, bits: 43)	TketeHenery
    50-bits minimum entropy:
        (length: 11, bits: 53)	Soecil]Ded^
        (length: 12, bits: 54)	Pusi=Nliche4
        (length: 12, bits: 53)	Lrds0OryUts]
        (length: 16, bits: 53)	Press_ExtricJck_
        (length: 12, bits: 54)	Quyely!KeNr{
        (length: 11, bits: 50)	WferySinin"
        (length: 11, bits: 50)	_JolooYmpt%
        (length: 10, bits: 53)	Bri?MgWrtz
        (length: 13, bits: 51)	ReZoidZnsist_
        (length: 10, bits: 52)	Men-VuePn}
    60-bits minimum entropy:
        (length: 11, bits: 62)	!MyMu&Jc$Xe
        (length: 13, bits: 62)	@ErHi<Xtrugh<
        (length: 16, bits: 63)	QueIlePrmentMot7
        (length: 14, bits: 62)	@IleghBrosBulp
        (length: 16, bits: 64)	^Undpt{OrHiKings
        (length: 13, bits: 63)	0De<Pet=Xing/
        (length: 17, bits: 64)	ZrdDicConcon~Nore
        (length: 15, bits: 62)	-WyneFceorWeler
        (length: 15, bits: 62)	{RteSitionRcyJw
        (length: 14, bits: 61)	,PcJckipsWrdLt
    70-bits minimum entropy:
        (length: 17, bits: 72)	Xbo(Mngens7Rferse
        (length: 20, bits: 73)	;Fon9KnonsDess3Rpers
        (length: 15, bits: 70)	[KkithLney=Que+
        (length: 17, bits: 70)	Quot#LizedoYeeze*
        (length: 18, bits: 73)	VredKbly8SqueCold:
        (length: 18, bits: 71)	&Unk&Qued&WreFound
        (length: 16, bits: 72)	Xyny9JbbyNolUnsk
        (length: 21, bits: 74)	Mnic/ZilingOusNopyMte
        (length: 18, bits: 71)	=QuiripRtedvyUped?
        (length: 18, bits: 70)	@JmiTtillyZurCtion
