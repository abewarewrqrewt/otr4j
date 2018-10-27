
package net.java.otr4j.messages;

import net.java.otr4j.api.OtrException;
import net.java.otr4j.crypto.OtrCryptoException;
import net.java.otr4j.io.OtrInputStream;
import net.java.otr4j.io.OtrOutputStream;
import net.java.otr4j.test.dummyclient.DummyClient;
import org.apache.commons.lang3.RandomStringUtils;
import org.apache.commons.lang3.RandomUtils;
import org.junit.Test;

import javax.crypto.interfaces.DHPublicKey;
import java.net.ProtocolException;

import static net.java.otr4j.api.InstanceTag.HIGHEST_TAG;
import static net.java.otr4j.api.InstanceTag.SMALLEST_TAG;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.not;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;

public class DataMessageTest {

    String snippets[] = {
            "བོད་རིགས་ཀྱི་བོད་སྐད་བརྗོད་པ་དང་ བོད་རིགས་མང་ཆེ་བ་ནི་ནང་ཆོས་བྱེད་པ་དང་ འགའ་ཤས་བོན་ཆོས་བྱེད་ཀྱིན་ཡོད་ འགའ་ཤས་ཁ་ཆེའི་ཆོས་བྱེད་ཀྱིན་ཡོད། ནང་ཆོས་ཀྱིས་བོད་ཀྱི་སྒྱུ་རྩལ་དང་ཟློས་གར་ཁང་རྩིག་བཟོ་རིག་ལ་སོགས་ལ་ཤུགས་རྐྱེན་ཆེན་པོ་འཐེབ་ཀྱིན་ཡོད།",
            "تبتی قوم (Tibetan people) (تبتی: བོད་པ་، وائلی: Bodpa، چینی: 藏族؛ پنین: Zàng",
            "تبتی قوم سے ربط رکھنے والے صفحات",
            "Учените твърдят, че тибетците нямат проблеми с разредения въздух и екстремни студове, защото не са хора. Размус Нилсен от университета Бъркли и неговите сътрудници от лабораторията за ДНК изследвания в Китай твърдят, че тибетците",
            "Câung-cŭk (藏族, Câung-ngṳ̄: བོད་པ་) sê Câung-kṳ̆ (bău-guók gĭng-dáng gì Să̤-câung) gì siŏh ciáh mìng-cŭk, iâ sê Dṳ̆ng-guók guăng-huŏng giĕ-dêng gì „Dṳ̆ng-huà Mìng-cŭk“ cĭ ék.",
            "チベット系民族（チベットけいみんぞく）は、主としてユーラシア大陸中央部のチベット高原上に分布する民族で、モンゴロイドに属する。",
            "原始汉人与原始藏缅人约在公元前4000年左右分开。原始汉人逐渐移居到黄河流域从事农业，而原始藏缅人则向西南迁徙并从事游牧业。而之后藏族与缅族又进一步的分离。[1]原始藏缅人屬於古羌人系統，发羌入藏為吐蕃王朝發跡的一種歷史學觀點",
            "Տիբեթացիներ (ինքնանվանումը՝ պյոբա), ժողովուրդ, Տիբեթի արմատական բնակչությունը։ Բնակվում են Չինաստանում (Տիբեթի ինքնավար շրջան, Դանսու, Ցինհայ, Սըչուան, Ցուննան նահանգներ), որոշ մասը՝ Հնդկաստանում, Նեպալում և Բութանում։ Ընդհանուր թիվը՝ մոտ 5 մլն (1978)։ Խոսում ենտիբեթերենի բարբառներով։ Հիմնական կրոնը լամայականությունն է (բուդդայականության հյուսիսային ճյուղ)։ Տիբեթացիների կեսից ավելին լեռնային նստակյաց երկրագործներ են (աճեցնում են հիմնականում գարի, ցորեն, բրինձ), մնացածներրը՝ կիսանստակյաց հողագործ-անասնապահներ և թափառակեցիկ անասնապահներ (բուծում են եղնայծ, ձի, ոչխար, այծ)։ Զարգացած են արհեստները։ XX դ․ սկզբին ստեղծվել են արդիական մի քանի փոքր ձեռնարկություններ",
            "... Gezginci olarak yabancılarla karışanlar \"شْتَن Xotan\" ve \"تبت Tübüt\" halkı ile \"طَنغُت Tenğüt\"lerin bir kısmıdır.\"[1] ve \"Tübütlüler تبت adında birinin oğullarıdır. Bu, Yemenli bir kimsedir, orada birini öldürmüş, korkusundan kaçmış, bir gemiye binerek Çine gelmiş, \"Tibet\" ülkesi onun hoşuna gitmiş, orada yerleşmiş; çoluğu çocuğu çoğalmış, torunları Türk topraklarından bin beşyüz fersah yer almışlar, Çin ülkesi Tibetin doğu tarafındadır.\"[2] şeklinde yorumlar.",
            "Tibeťané jsou domorodí obyvatelé Tibetu a přilehlých oblastí Centrální Asie, počínaje Myanmarem na jihovýchodě a Čínskou lidovou republikou na východě konče. Počet Tibeťanů je těžko odhadnutelný, podle údajů Ústřední tibetské správy populace Tibeťanů klesla od roku 1959 z 6,3 milionů na 5,4 milionů",
            "ئاچاڭ مىللىتى - بەيزۇ مىللىتى - بونان مىللىتى - بۇلاڭ مىللىتى - بۇيى مىللىت - چوسون مىللىتى - داغۇر مىللىتى - دەيزۇ مىللىتى - دېئاڭ مىللىتى - دۇڭشياڭ مىللىتى - دۇڭزۇ مىللىتى - دۇلۇڭ مىللىتى - رۇس مىللىتى - ئورۇنچون مىللىتى - ئېۋېنكى مىللىتى - گېلاۋ مىللىتى - ھانى مىللىتى - قازاق مىللىتى - خېجى مىللىتى - خۇيزۇ مىللىتى - گاۋشەن مىللىتى - خەنزۇ مىللىتى - كىنو مىللىتى - جىڭزۇ مىللىتى - جخڭپو مىللىتى - قىرغىز مىللىتى - لاخۇ مىللىتى - لىزۇ مىللىتى - لىسۇ مىللىتى - لوبا مىللىتى - مانجۇ مىللىتى - ماۋنەن مىللىتى - مېنبا مىللىتى - موڭغۇل مىللىتى - مياۋزۇ مىللىتى - مۇلاۋ مىللىتى - ناشى مىللىتى - نۇزۇ مىللىتى - پۇمى مىللىتى - چياڭزۇ مىللىتى - سالار مىللىتى - شېزۇ مىللىتى - شۈيزۇلار - تاجىك مىللىتى - تاتار مىللىتى - تۇجيا مىللىتى - تۇزۇ مىللىتى - ۋازۇ مىللىتى - ئۇيغۇر مىللىتى - ئۆزبېك مىللىتى - شىبە مىللىتى - ياۋزۇ مىللىتى - يىزۇ مىللىتى - يۇغۇر مىللىتى - تىبەت مىللىتى - جۇاڭزۇ مىللىتى",
            "Miscellaneous Symbols and Pictographs[1][2]Official Unicode Consortium code chart (PDF)    0   1   2   3   4   5   6   7   8   9   A   B   C   D   E   FU+1F30x 🌀  🌁  🌂  🌃  🌄  🌅  🌆  🌇  🌈  🌉  🌊  🌋  🌌  🌍  🌎  🌏U+1F31x 🌐  🌑  🌒  🌓  🌔  🌕  🌖  🌗  🌘  🌙  🌚  🌛  🌜  🌝  🌞  🌟U+1F32x 🌠  🌡  🌢  🌣  🌤  🌥  🌦  🌧  🌨  🌩  🌪  🌫  🌬         U+1F33x 🌰  🌱  🌲  🌳  🌴  🌵  🌶  🌷  🌸  🌹  🌺  🌻  🌼  🌽  🌾  🌿U+1F34x 🍀  🍁  🍂  🍃  🍄  🍅  🍆  🍇  🍈  🍉  🍊  🍋  🍌  🍍  🍎  🍏U+1F35x 🍐  🍑  🍒  🍓  🍔  🍕  🍖  🍗  🍘  🍙  🍚  🍛  🍜  🍝  🍞  🍟U+1F36x 🍠  🍡  🍢  🍣  🍤  🍥  🍦  🍧  🍨  🍩  🍪  🍫  🍬  🍭  🍮  🍯U+1F37x 🍰  🍱  🍲  🍳  🍴  🍵  🍶  🍷  🍸  🍹  🍺  🍻  🍼  🍽     U+1F38x 🎀  🎁  🎂  🎃  🎄  🎅  🎆  🎇  🎈  🎉  🎊  🎋  🎌  🎍  🎎  🎏U+1F39x 🎐  🎑  🎒  🎓  🎔  🎕  🎖  🎗  🎘  🎙  🎚  🎛  🎜  🎝  🎞  🎟U+1F3Ax 🎠  🎡  🎢  🎣  🎤  🎥  🎦  🎧  🎨  🎩  🎪  🎫  🎬  🎭  🎮  🎯U+1F3Bx 🎰  🎱  🎲  🎳  🎴  🎵  🎶  🎷  🎸  🎹  🎺  🎻  🎼  🎽  🎾  🎿U+1F3Cx 🏀  🏁  🏂  🏃  🏄  🏅  🏆  🏇  🏈  🏉  🏊  🏋  🏌  🏍  🏎 U+1F3Dx                 🏔  🏕  🏖  🏗  🏘  🏙  🏚  🏛  🏜  🏝  🏞  🏟U+1F3Ex 🏠  🏡  🏢  🏣  🏤  🏥  🏦  🏧  🏨  🏩  🏪  🏫  🏬  🏭  🏮  🏯U+1F3Fx 🏰  🏱  🏲  🏳  🏴  🏵  🏶  🏷                             U+1F40x 🐀  🐁  🐂  🐃  🐄  🐅  🐆  🐇  🐈  🐉  🐊  🐋  🐌  🐍  🐎  🐏U+1F41x 🐐  🐑  🐒  🐓  🐔  🐕  🐖  🐗  🐘  🐙  🐚  🐛  🐜  🐝  🐞  🐟U+1F42x 🐠  🐡  🐢  🐣  🐤  🐥  🐦  🐧  🐨  🐩  🐪  🐫  🐬  🐭  🐮  🐯U+1F43x 🐰  🐱  🐲  🐳  🐴  🐵  🐶  🐷  🐸  🐹  🐺  🐻  🐼  🐽  🐾  🐿U+1F44x 👀  👁  👂  👃  👄  👅  👆  👇  👈  👉  👊  👋  👌  👍  👎  👏U+1F45x 👐  👑  👒  👓  👔  👕  👖  👗  👘  👙  👚  👛  👜  👝  👞  👟U+1F46x 👠  👡  👢  👣  👤  👥  👦  👧  👨  👩  👪  👫  👬  👭  👮  👯U+1F47x 👰  👱  👲  👳  👴  👵  👶  👷  👸  👹  👺  👻  👼  👽  👾  👿U+1F48x 💀  💁  💂  💃  💄  💅  💆  💇  💈  💉  💊  💋  💌  💍  💎  💏U+1F49x 💐  💑  💒  💓  💔  💕  💖  💗  💘  💙  💚  💛  💜  💝  💞  💟U+1F4Ax 💠  💡  💢  💣  💤  💥  💦  💧  💨  💩  💪  💫  💬  💭  💮  💯U+1F4Bx 💰  💱  💲  💳  💴  💵  💶  💷  💸  💹  💺  💻  💼  💽  💾  💿U+1F4Cx 📀  📁  📂  📃  📄  📅  📆  📇  📈  📉  📊  📋  📌  📍  📎  📏U+1F4Dx 📐  📑  📒  📓  📔  📕  📖  📗  📘  📙  📚  📛  📜  📝  📞  📟U+1F4Ex 📠  📡  📢  📣  📤  📥  📦  📧  📨  📩  📪  📫  📬  📭  📮  📯U+1F4Fx 📰  📱  📲  📳  📴  📵  📶  📷  📸  📹  📺  📻  📼  📽  📾 U+1F50x 🔀  🔁  🔂  🔃  🔄  🔅  🔆  🔇  🔈  🔉  🔊  🔋  🔌  🔍  🔎  🔏U+1F51x 🔐  🔑  🔒  🔓  🔔  🔕  🔖  🔗  🔘  🔙  🔚  🔛  🔜  🔝  🔞  🔟U+1F52x 🔠  🔡  🔢  🔣  🔤  🔥  🔦  🔧  🔨  🔩  🔪  🔫  🔬  🔭  🔮  🔯U+1F53x 🔰  🔱  🔲  🔳  🔴  🔵  🔶  🔷  🔸  🔹  🔺  🔻  🔼  🔽  🔾  🔿U+1F54x 🕀  🕁  🕂  🕃  🕄  🕅  🕆  🕇  🕈  🕉  🕊                 U+1F55x 🕐  🕑  🕒  🕓  🕔  🕕  🕖  🕗  🕘  🕙  🕚  🕛  🕜  🕝  🕞  🕟U+1F56x 🕠  🕡  🕢  🕣  🕤  🕥  🕦  🕧  🕨  🕩  🕪  🕫  🕬  🕭  🕮  🕯U+1F57x 🕰  🕱  🕲  🕳  🕴  🕵  🕶  🕷  🕸  🕹      🕻  🕼  🕽  🕾  🕿U+1F58x 🖀  🖁  🖂  🖃  🖄  🖅  🖆  🖇  🖈  🖉  🖊  🖋  🖌  🖍  🖎  🖏U+1F59x 🖐  🖑  🖒  🖓  🖔  🖕  🖖  🖗  🖘  🖙  🖚  🖛  🖜  🖝  🖞  🖟U+1F5Ax 🖠  🖡  🖢  🖣      🖥  🖦  🖧  🖨  🖩  🖪  🖫  🖬  🖭  🖮  🖯U+1F5Bx 🖰  🖱  🖲  🖳  🖴  🖵  🖶  🖷  🖸  🖹  🖺  🖻  🖼  🖽  🖾  🖿U+1F5Cx 🗀  🗁  🗂  🗃  🗄  🗅  🗆  🗇  🗈  🗉  🗊  🗋  🗌  🗍  🗎  🗏U+1F5Dx 🗐  🗑  🗒  🗓  🗔  🗕  🗖  🗗  🗘  🗙  🗚  🗛  🗜  🗝  🗞  🗟U+1F5Ex 🗠  🗡  🗢  🗣  🗤  🗥  🗦  🗧  🗨  🗩  🗪  🗫  🗬  🗭  🗮  🗯U+1F5Fx 🗰  🗱  🗲  🗳  🗴  🗵  🗶  🗷  🗸  🗹  🗺  🗻  🗼  🗽  🗾  🗿",
            "😀 😁  😂  😃  😄  😅  😆  😇  😈  😉  😊  😋  😌  😍  😎  😏U+1F61x 😐  😑  😒  😓  😔  😕  😖  😗  😘  😙  😚  😛  😜  😝  😞  😟U+1F62x 😠  😡  😢  😣  😤  😥  😦  😧  😨  😩  😪  😫  😬  😭  😮  😯U+1F63x 😰  😱  😲  😳  😴  😵  😶  😷  😸  😹  😺  😻  😼  😽  😾  😿U+1F64x 🙀  🙁  🙂          🙅  🙆  🙇  🙈  🙉  🙊  🙋  🙌  🙍  🙎  🙏",
            "🌀🌁🌂🌃🌄🌅🌆🌇🌈🌉🌊🌋🌌🌍🌎🌏🌐🌑🌒🌓🌔🌕🌖🌗🌘🌙🌚🌛🌜🌝🌞🌟🌠 🌰🌱🌲🌳🌴🌵🌷🌸🌹🌺🌻🌼🌽🌾🌿🍀🍁🍂🍃🍄🍅🍆🍇🍈🍉🍊🍋🍌🍍🍎🍏🍐🍑🍒🍓🍔🍕🍖🍗🍘🍙🍚🍛🍜🍝🍞🍟 🍠🍡🍢🍣🍤🍥🍦🍧🍨🍩🍪🍫🍬🍭🍮🍯🍰🍱🍲🍳🍴🍵🍶🍷🍸🍹🍺🍻🍼🎀🎁🎂🎃🎄🎅🎆🎇🎈🎉🎊🎋🎌🎍🎎🎏🎐🎑🎒🎓 🎠🎡🎢🎣🎤🎥🎦🎧🎨🎩🎪🎫🎬🎭🎮🎯🎰🎱🎲🎳🎴🎵🎶🎷🎸🎹🎺🎻🎼🎽🎾🎿🏀🏁🏂🏃🏄🏅🏆🏇🏈🏉🏊 🏠🏡🏢🏣🏤🏥🏦🏧🏨🏩🏪🏫🏬🏭🏮🏯🏰🐀🐁🐂🐃🐄🐅🐆🐇🐈🐉🐊🐋🐌🐍🐎🐏🐐🐑🐒🐓🐔🐕🐖🐗🐘🐙🐚🐛🐜🐝🐞🐟 🐠🐡🐢🐣🐤🐥🐦🐧🐨🐩🐪🐫🐬🐭🐮🐯🐰🐱🐲🐳🐴🐵🐶🐷🐸🐹🐺🐻🐼🐽🐾👀👂👃👄👅👆👇👈👉👊👋👌👍👎👏 👐👑👒👓👔👕👖👗👘👙👚👛👜👝👞👟👠👡👢👣👤👥👦👧👨👩👪👫👬👭👮👯👰👱👲👳👴👵👶👷👸👹👺👻👼👽👾👿 💀💁💂💃💄💅💆💇💈💉💊💋💌💍💎💏💐💑💒💓💔💕💖💘💙💚💛💜💝💞💟💠💡💢💣💤💥💦💧💨💩💪💫💬💭💮💯 💰💱💲💳💴💵💶💷💸💹💺💻💼💽💾💿📀📁📂📃📄📅📆📇📈📉📊📋📌📍📎📏📐📑📒📓📔📕📖📗📘📙📚📛📜📝📞📟 📠📡📢📣📤📥📦📧📨📩📪📫📬📭📮📯📰📱📲📳📴📵📶📷📹📺📻📼🔀🔁🔂🔃🔄🔅🔆🔇🔈🔉🔊🔋🔌🔍🔎🔏 🔐🔑🔒🔓🔔🔕🔖🔗🔘🔙🔚🔛🔜🔝🔞🔟🔠🔡🔢🔣🔤🔥🔦🔧🔨🔩🔪🔫🔬🔭🔮🔯🔰🔱🔲🔳🔴🔵🔶🔷🔸🔹🔺🔻🔼🔽 🕐🕑🕒🕓🕔🕕🕖🕗🕘🕙🕚🕛🕜🕝🕞🕟🕠🕡🕢🕣🕤🕥🕦🕧🗻🗼🗽🗾🗿 😁😂😃😄😅😆😇😈😉😊😋😌😍😎😏😐😒😓😔😖😘😚😜😝😞😠😡😢😣😤😥😨😩😪😫😭😰😱😲😳😵😶😷 😸😹😺😻😼😽😾😿🙀🙅🙆🙇🙈🙉🙊🙋🙌🙍🙎🙏 🚀🚁🚂🚃🚄🚅🚆🚇🚈🚉🚊🚋🚌🚍🚎🚏🚐🚑🚒🚓🚔🚕🚖🚗🚘🚙🚚🚛🚜🚝🚞🚟🚠🚡🚢🚣🚤🚥🚦🚧🚨🚩🚪 🚫🚬🚭🚮🚯🚰🚱🚲🚳🚴🚵🚶🚷🚸🚹🚺🚻🚼🚽🚾🚿🛀🛁🛂🛃🛄🛅",
            "Royal Thai (ราชาศัพท์): (influenced by Khmer) used when addressing members of the royal family or describing their activities. ",
            "טיילאנדיש (ภาษาไทย) איז די באַאַמטער שפּראַך פון טיילאנד און די טייַלענדיש מענטשן. 20,000,000 מענטשן רעדן די שפּראַך, פון זיי -4,700,000 רעדן זי ווי זייער מוטערשפראך.",
            "the Khmer term is ជើងអក្សរ cheung âksâr, meaning \"foot of a letter\"",
            "중화인민공화국에서는 기본적으로 한족은 1명, 일반 소수민족은 2명까지 낳을 수 있지만 3000m 이상의 산지나 고원에서 사는 티베트족은 3명까지 낳을 수 있다",
            "पाठ्यांशः अत्र उपलभ्यतेसर्जनसामान्यलक्षणम्/Share-Alike License; अन्ये नियमाः आन्विताः भवेयुः । दृश्यताम्Terms of use अधिकविवरणाय ।",
            "থাইল্যান্ডের প্রায় ২ কোটি লোকের মাতৃভাষা থাই, যা থাইল্যান্ডের জাতীয় ভাষা। এছাড়া দ্বিতীয় ভাষা হিসেবে আরও প্রায় ২ কোটি লোক আদর্শ থাই ভাষাতে কথা বলতে পারেন। থাইল্যান্ড ছাড়াও মিডওয়ে দ্বীপপুঞ্জ, সিঙ্গাপুর, সংযুক্ত আরব আমিরাত এবং মার্কিন যুক্তরাষ্ট্রে থাই ভাষা প্রচলিত। থাই ভাষাতে \"থাই\" শব্দটির অর্থ \"স্বাধীনতা\"।",
            "திபெத்துக்கு வெளியே வாழும் திபெத்தியர்கள் தெரிவிக்கிறார்கள்",
            "អក្សរសាស្រ្តខែ្មរមានប្រវ៌ត្តជាងពីរពាន់ឆ្នាំមកហើយ ចាប់តាំងពីកំនើតប្រទេសខែ្មរដំបូងមកម្លោះ។ ជនជាតិខែ្មរសម៍យបុរាណបានសំរួលអក្សរខ្មែរមរពីអក្សរសំស្ក្រឹត។",
            "촇֊儠蛸ᣞ㎧贲웆꘠샾䛱郣굉ᵏ椚⣦赢霯⟜㜈幫틃㭯㝻㖎즋鶚宬㑍黡ㆇར렀네𩗗ᄉᄔ嚖蒙⚙摍⨔裔쐬䈇⩌휥㱱蔿⺌ꂤ󌐓쌹᳛쯀汣使ⶓ昌沐꽔⟰錉𨴃⤋冖땀歷皼缔㉚旮쑗匎˺硚鈈ၕ凣碁蜨嬣ᬯ",
            "㢐򇐫큨败奊惆꘤쀉狨㏲㿯뇢縿ꅀ턺䆽靏鱸ꖽ圼І๠㊷槥岾鑨鬦𫭪뵝韻ᒢ覲ڸ巈󡡡虷빉鴟ｵ듷쁼ẓ➱淨㖌甩⦼躂௬ဃ젃扒䠾ㄱ뗄஄䶁늪닫伆牞Ｊ",
    };
    String whackNullSnippets[] = {
            "asdf\0\0",
            "\0\0\0\0\0\0\0",
            "asdfasdf\0\0aadsfasdfa\0",
            "\0\0អក្សរសាស្រ្តខែ្មរមានប្រវ៌ត្តជាងពីរពាន់ឆ្នាំមកហើយ",
    };

    @Test
    public void testWhackUnicodeWithNull() throws OtrException {
        String msg;
        DummyClient[] convo = DummyClient.getConversation();
        DummyClient alice = convo[0];
        DummyClient bob = convo[1];
        DummyClient.forceStartOtr(alice, bob);

        for (int i = 0; i < 100; i++) {
            msg = snippets[RandomUtils.nextInt(0, whackNullSnippets.length - 1)];
            alice.send(bob.getAccount(), msg);
            assertThat("Message has been transferred encrypted.",
                    alice.getConnection().getSentMessage(),
                    not(equalTo(msg)));
            assertEquals("Received message should match sent message.",
                    // remove nulls like SerializationUtils does
                    msg.replace('\0', '?'),
                    bob.pollReceivedMessage().getContent());

            msg = snippets[RandomUtils.nextInt(0, whackNullSnippets.length - 1)];
            bob.send(alice.getAccount(), msg);
            assertThat("Message has been transferred encrypted.",
                    bob.getConnection().getSentMessage(),
                    not(equalTo(msg)));
            assertEquals("Received message should match sent message.",
                    // remove nulls like SerializationUtils does
                    msg.replace('\0', '?'),
                    alice.pollReceivedMessage().getContent());
        }
        bob.exit();
        alice.exit();
    }

    @Test
    public void testWithRandomlyGeneratedUnicode() throws OtrException {
        String msg;
        String sent;
        String received;
        DummyClient[] convo = DummyClient.getConversation();
        DummyClient alice = convo[0];
        DummyClient bob = convo[1];
        DummyClient.forceStartOtr(alice, bob);

        for (int i = 0; i < 1000; i++) {
            int aliceSize = RandomUtils.nextInt(1, 100000);
            msg = RandomStringUtils.random(aliceSize);
            alice.send(bob.getAccount(), msg);
            sent = alice.getConnection().getSentMessage();
            assertThat("Message has been transferred encrypted.", sent, not(equalTo(msg)));
            received = bob.pollReceivedMessage().getContent();
            assertEquals("String lengths should be equal", msg.length(), received.length());
            assertEquals("Received message should match sent message.",
                    // remove nulls like SerializationUtils does
                    msg.replace('\0', '?'),
                    received);

            int bobSize = RandomUtils.nextInt(1, 100000);
            msg = RandomStringUtils.random(bobSize);
            bob.send(alice.getAccount(), msg);
            sent = bob.getConnection().getSentMessage();
            assertThat("Message has been transferred encrypted.", sent, not(equalTo(msg)));
            received = alice.pollReceivedMessage().getContent();
            assertEquals("String lengths should be equal", msg.length(), received.length());
            assertEquals("Received message should match sent message.",
                    // remove nulls like SerializationUtils does
                    msg.replace('\0', '?'),
                    received);
        }
        bob.exit();
        alice.exit();
    }

    @Test
    public void testForceStartWithHardCodedSnippets() throws OtrException {
        String msg;
        DummyClient[] convo = DummyClient.getConversation();
        DummyClient alice = convo[0];
        DummyClient bob = convo[1];
        DummyClient.forceStartOtr(alice, bob);

        for (int i = 0; i < 100; i++) {
            msg = snippets[RandomUtils.nextInt(0, snippets.length - 1)];
            alice.send(bob.getAccount(), msg);
            assertThat("Message has been transferred encrypted.",
                    alice.getConnection().getSentMessage(),
                    not(equalTo(msg)));
            assertEquals("Received message is different from the sent message.",
                    msg, bob.pollReceivedMessage().getContent());
            msg = snippets[RandomUtils.nextInt(0, snippets.length - 1)];
            bob.send(alice.getAccount(), msg);
            assertThat("Message has been transferred encrypted.",
                    bob.getConnection().getSentMessage(),
                    not(equalTo(msg)));
            assertEquals("Received message is different from the sent message.",
                    msg, alice.pollReceivedMessage().getContent());
        }
        bob.exit();
        alice.exit();
    }

    @Test
    public void testDummyClientWithHardCodedSnippets() throws OtrException {
        String msg;
        DummyClient[] convo = DummyClient.getConversation();
        DummyClient alice = convo[0];
        DummyClient bob = convo[1];

        for (int i = 0; i < 100; i++) {
            msg = snippets[RandomUtils.nextInt(0, snippets.length - 1)];
            alice.send(bob.getAccount(), msg);
            assertThat("plain transfer via DummyClient",
                    alice.getConnection().getSentMessage(),
                    equalTo(msg));
            assertEquals("Received message is different from the sent message.",
                    msg, bob.pollReceivedMessage().getContent());
            msg = snippets[RandomUtils.nextInt(0, snippets.length - 1)];
            bob.send(alice.getAccount(), msg);
            assertThat("plain transfer via DummyClient",
                    bob.getConnection().getSentMessage(),
                    equalTo(msg));
            assertEquals("Received message is different from the sent message.",
                    msg, alice.pollReceivedMessage().getContent());
        }
        bob.exit();
        alice.exit();
    }

    @Test
    public void testSerializingDataMessage() throws OtrCryptoException, ProtocolException {
        final byte[] expected = new byte[] {0, 3, 3, 0, 0, 1, 0, -1, -1, -1, -1, 0, 5, -26, 117, -25, 2, -106, -64, -42, 0, 0, 0, -64, -58, 61, 107, -16, -57, -110, -50, 64, 32, -113, 75, -106, -38, -23, 76, 100, -82, 37, 113, 19, 59, 41, -16, 88, -20, -93, -19, -38, -90, -42, 99, 1, -80, 120, 68, 118, 64, -121, -18, 90, 54, -23, 96, -85, -6, -33, 17, -22, -29, 63, 123, -45, 64, 61, -95, 84, -59, 20, 40, -14, -65, 33, -128, -61, -39, -4, 38, 41, -73, 127, 116, -82, -29, -71, 31, -118, -109, -82, 15, 104, 31, 11, 70, 117, 109, -19, 93, 15, -51, -52, -73, 11, -34, -17, 119, -92, 8, 17, 59, 75, -55, 26, 2, 111, -7, -106, -74, 123, 88, 97, 53, -78, -124, 113, -59, 31, 103, -78, -128, 63, -96, -82, 97, -44, 59, 32, -21, -86, -89, 94, 72, 70, -24, -111, -88, 81, -109, 107, -50, 120, -81, -64, 54, -47, -68, -22, 117, -90, -34, -12, -34, 8, -63, -47, -57, -45, -112, 26, -87, 115, -99, -8, 50, 7, 93, 33, -89, 48, -8, 64, 112, -126, -50, -52, 79, -37, -13, 93, -50, -65, -63, 113, 31, 21, 84, -124, -116, -34, -110, 85, -105, -5, 59, -1, 0, 106, -108, 69, -52, 10, 0, 0, 1, 119, 29, -69, 94, -26, -71, 40, 37, 104, -19, -16, 39, 126, 104, 122, 118, 112, -44, 120, 23, 124, -92, 50, -27, -70, 66, -123, -42, -18, 113, 101, 86, 126, 95, -105, 104, -38, 87, -27, -22, 49, -53, -121, 103, 58, 97, 3, -42, -38, -5, 24, 24, -42, 124, 68, 31, -112, -76, -74, -2, 103, -27, 88, 93, 39, 116, 29, 0, 17, -122, -88, 1, 41, 32, 67, 109, -5, 4, 19, 71, -94, 95, -63, 14, -126, -95, 70, -101, 25, 87, -122, -91, -115, -68, 83, 111, -92, -93, -108, -67, 10, -93, -111, 40, -36, -1, -127, -96, -42, -58, -28, 81, 63, -93, -44, -26, -79, 3, -4, 0, -50, 63, 22, -29, 122, -25, -127, -100, -66, -98, 104, 80, 5, -110, 52, -78, -61, 5, 78, -112, -99, 115, 24, -25, -106, 119, -42, -79, 89, -87, -104, 112, -39, 114, -26, 59, -104, -85, -37, -127, -81, -118, -100, 65, 10, -43, -27, -12, 126, -118, 84, 25, -62, 96, -7, 81, 105, 30, -62, 112, 77, -72, -83, -90, -39, 117, -11, -113, 81, -22, 26, 81, -91, -82, -51, 92, -83, 91, 53, 1, -6, -45, 7, 119, -10, 5, -103, 8, -36, 89, 127, 101, 72, -81, -46, 103, -126, -1, -21, 2, 121, -43, 97, 38, 91, 62, 60, -81, -80, -77, 26, 58, -3, -124, 4, 60, 96, 59, 116, -58, 26, 96, -23, 15, -12, 45, -18, 77, 64, -126, -40, -67, 9, 126, -32, -28, 40, -58, -110, -82, 63, -110, -74, -117, -19, 95, 37, 107, 52, -42, 1, 22, 74, -98, -123, -63, -79, -1, -17, 121, 11, -39, -60, -104, -25, 67, 30, -84, 23, 113, 51, 87, -2, 29, -126, 40, -82, 74, -103, -54, 95, 77, 49, -23, -51, -123, 79, -102, -114, -71, -24, -2, 27, -102, 47, -69, 10, 90, -80, -3, 71, -42, 66, -124, 78, 126, -88, -80, -83, -41, -38, -101, 122, -74, -120, -77, 93, 83, 44, -113, -22, 16, -120, -16, -67, 3, 65, 75, 79, 76, -95, 46, -52, -59, 57, -75, -10, -88, 28, 44, -31, -104, 108, -115, -61, 31, -47, -71, 127, -124, 115, -96, 56, -92, 61, -38, -66, 49, 81, -51, -59, -116, -110, -8, 24, 31, 101, -116, 87, -95, 17, 119, 58, -124, -13, -115, 0, 0, 0, 40, -60, -52, -98, 72, 86, -30, 99, 30, 113, -123, 3, 61, -29, -47, -98, -44, 67, 116, -28, 108, 29, -3, -8, 4, 102, 127, -37, 30, 105, -75, -30, -76, -101, -118, -30, 111, 67, 33, -2, -55};
        final DHPublicKey dhPublicKey = new OtrInputStream(new byte[]{0, 0, 0, -64, -58, 61, 107, -16, -57, -110, -50, 64, 32, -113, 75, -106, -38, -23, 76, 100, -82, 37, 113, 19, 59, 41, -16, 88, -20, -93, -19, -38, -90, -42, 99, 1, -80, 120, 68, 118, 64, -121, -18, 90, 54, -23, 96, -85, -6, -33, 17, -22, -29, 63, 123, -45, 64, 61, -95, 84, -59, 20, 40, -14, -65, 33, -128, -61, -39, -4, 38, 41, -73, 127, 116, -82, -29, -71, 31, -118, -109, -82, 15, 104, 31, 11, 70, 117, 109, -19, 93, 15, -51, -52, -73, 11, -34, -17, 119, -92, 8, 17, 59, 75, -55, 26, 2, 111, -7, -106, -74, 123, 88, 97, 53, -78, -124, 113, -59, 31, 103, -78, -128, 63, -96, -82, 97, -44, 59, 32, -21, -86, -89, 94, 72, 70, -24, -111, -88, 81, -109, 107, -50, 120, -81, -64, 54, -47, -68, -22, 117, -90, -34, -12, -34, 8, -63, -47, -57, -45, -112, 26, -87, 115, -99, -8, 50, 7, 93, 33, -89, 48, -8, 64, 112, -126, -50, -52, 79, -37, -13, 93, -50, -65, -63, 113, 31, 21, 84, -124, -116, -34, -110, 85, -105, -5}).readDHPublicKey();
        final int senderKeyID = 98989543;
        final int receiverKeyID = 43434198;
        final byte[] ctr = new byte[] {0x3b, (byte) 0xff, 0x00, 0x6a, (byte) 0x94, 0x45, (byte) 0xcc, 0x0a};
        final byte[] message = new byte[] {29, -69, 94, -26, -71, 40, 37, 104, -19, -16, 39, 126, 104, 122, 118, 112, -44, 120, 23, 124, -92, 50, -27, -70, 66, -123, -42, -18, 113, 101, 86, 126, 95, -105, 104, -38, 87, -27, -22, 49, -53, -121, 103, 58, 97, 3, -42, -38, -5, 24, 24, -42, 124, 68, 31, -112, -76, -74, -2, 103, -27, 88, 93, 39, 116, 29, 0, 17, -122, -88, 1, 41, 32, 67, 109, -5, 4, 19, 71, -94, 95, -63, 14, -126, -95, 70, -101, 25, 87, -122, -91, -115, -68, 83, 111, -92, -93, -108, -67, 10, -93, -111, 40, -36, -1, -127, -96, -42, -58, -28, 81, 63, -93, -44, -26, -79, 3, -4, 0, -50, 63, 22, -29, 122, -25, -127, -100, -66, -98, 104, 80, 5, -110, 52, -78, -61, 5, 78, -112, -99, 115, 24, -25, -106, 119, -42, -79, 89, -87, -104, 112, -39, 114, -26, 59, -104, -85, -37, -127, -81, -118, -100, 65, 10, -43, -27, -12, 126, -118, 84, 25, -62, 96, -7, 81, 105, 30, -62, 112, 77, -72, -83, -90, -39, 117, -11, -113, 81, -22, 26, 81, -91, -82, -51, 92, -83, 91, 53, 1, -6, -45, 7, 119, -10, 5, -103, 8, -36, 89, 127, 101, 72, -81, -46, 103, -126, -1, -21, 2, 121, -43, 97, 38, 91, 62, 60, -81, -80, -77, 26, 58, -3, -124, 4, 60, 96, 59, 116, -58, 26, 96, -23, 15, -12, 45, -18, 77, 64, -126, -40, -67, 9, 126, -32, -28, 40, -58, -110, -82, 63, -110, -74, -117, -19, 95, 37, 107, 52, -42, 1, 22, 74, -98, -123, -63, -79, -1, -17, 121, 11, -39, -60, -104, -25, 67, 30, -84, 23, 113, 51, 87, -2, 29, -126, 40, -82, 74, -103, -54, 95, 77, 49, -23, -51, -123, 79, -102, -114, -71, -24, -2, 27, -102, 47, -69, 10, 90, -80, -3, 71, -42, 66, -124, 78, 126, -88, -80, -83, -41, -38, -101, 122, -74, -120, -77, 93, 83, 44, -113, -22, 16, -120, -16, -67, 3, 65, 75, 79, 76, -95, 46, -52, -59, 57, -75, -10, -88, 28, 44, -31, -104, 108, -115, -61, 31, -47, -71, 127, -124, 115, -96, 56, -92, 61, -38};
        final byte[] mac = new byte[] {-66, 49, 81, -51, -59, -116, -110, -8, 24, 31, 101, -116, 87, -95, 17, 119, 58, -124, -13, -115};
        final byte[] oldMacKeys = new byte[] {-60, -52, -98, 72, 86, -30, 99, 30, 113, -123, 3, 61, -29, -47, -98, -44, 67, 116, -28, 108, 29, -3, -8, 4, 102, 127, -37, 30, 105, -75, -30, -76, -101, -118, -30, 111, 67, 33, -2, -55};
        final DataMessage input = new DataMessage(3, (byte) 0, senderKeyID, receiverKeyID, dhPublicKey,
                ctr, message, mac, oldMacKeys, SMALLEST_TAG, HIGHEST_TAG);
        final byte[] result = new OtrOutputStream().write(input).toByteArray();
        assertArrayEquals(expected, result);
    }
}
