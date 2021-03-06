/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */

package net.java.otr4j.api;

import net.java.otr4j.api.Session.Version;
import net.java.otr4j.crypto.DSAKeyPair;
import net.java.otr4j.crypto.OtrCryptoEngine;
import net.java.otr4j.crypto.ed448.EdDSAKeyPair;
import net.java.otr4j.crypto.ed448.Point;
import net.java.otr4j.util.BlockingSubmitter;
import net.java.otr4j.util.ConditionalBlockingQueue;
import net.java.otr4j.util.ConditionalBlockingQueue.Predicate;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.net.ProtocolException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collections;
import java.util.HashSet;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.logging.Level;
import java.util.logging.Logger;

import static java.lang.Integer.MAX_VALUE;
import static java.util.Arrays.asList;
import static java.util.Objects.requireNonNull;
import static net.java.otr4j.api.OtrPolicy.ALLOW_V2;
import static net.java.otr4j.api.OtrPolicy.ALLOW_V3;
import static net.java.otr4j.api.OtrPolicy.ALLOW_V4;
import static net.java.otr4j.api.OtrPolicy.OPPORTUNISTIC;
import static net.java.otr4j.api.OtrPolicy.OTRL_POLICY_MANUAL;
import static net.java.otr4j.api.SessionStatus.ENCRYPTED;
import static net.java.otr4j.api.SessionStatus.FINISHED;
import static net.java.otr4j.api.SessionStatus.PLAINTEXT;
import static net.java.otr4j.crypto.DSAKeyPair.generateDSAKeyPair;
import static net.java.otr4j.session.OtrSessionManager.createSession;
import static net.java.otr4j.util.Arrays.contains;
import static net.java.otr4j.util.BlockingQueuesTestUtils.drop;
import static net.java.otr4j.util.BlockingQueuesTestUtils.rearrangeFragments;
import static net.java.otr4j.util.BlockingQueuesTestUtils.shuffle;
import static org.bouncycastle.util.encoders.Base64.toBase64String;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

// TODO handle case where we store skipped message keys such that we can decrypt message that is received out-of-order, i.e. later than it was supposed to arrive.
// FIXME add test to prove that we can start new (D)AKE in encrypted/finished Message state.
// TODO add method to assert OTR-encoded data (and Fragment data) over communication channel as opposed to "not equals to original message".
public class SessionTest {

    private static final SecureRandom RANDOM = new SecureRandom();

    private static final String OTRv23QueryMessage = "<p>?OTRv23?\n"
            + "<span style=\"font-weight: bold;\">Bob@Wonderland/</span> has requested an <a href=\"http://otr.cypherpunks.ca/\">Off-the-Record private conversation</a>. However, you do not have a plugin to support that.\n"
            + "See <a href=\"http://otr.cypherpunks.ca/\">http://otr.cypherpunks.ca/</a> for more information.</p>";

    private static final String[] UNICODE_LINES = {
            "plainAscii",
            "བོད་རིགས་ཀྱི་བོད་སྐད་བརྗོད་པ་དང་ བོད་རིགས་མང་ཆེ་བ་ནི་ནང་ཆོས་བྱེད་པ་དང་",
            "تبتی قوم (Tibetan people)",
            "Учените твърдят, че тибетците нямат",
            "Câung-cŭk (藏族, Câung-ngṳ̄: བོད་པ་)",
            "チベット系民族（チベットけいみんぞく）",
            "原始汉人与原始藏缅人约在公元前4000年左右分开。",
            "Տիբեթացիներ (ինքնանվանումը՝ պյոբա),",
            "... Gezginci olarak",
            "شْتَن Xotan",
            "Tibeťané jsou",
            "ئاچاڭ- تىبەت مىللىتى",
            "Miscellaneous Symbols and Pictographs[1][2] Official Unicode Consortium code chart (PDF)",
            "Royal Thai (ราชาศัพท์)",
            "טיילאנדיש123 (ภาษาไทย)",
            "ជើងអក្សរ cheung âksâr",
            "중화인민공화국에서는 기본적으로 한족은 ",
            "पाठ्यांशः अत्र उपलभ्यतेसर्जनसामान्यलक्षणम्/Share-",
            "திபெத்துக்கு வெகள்",
            "អក្សរសាស្រ្តខែ្មរមានប្រវ៌ត្តជាងពីរពាន់ឆ្នាំមកហើយ ",
            "tabbackslashT\t",
            "backslashR\r",
            "NEWLINE\n",
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

    private static final String[] NULL_LINES = {
            "asdf\0\0",
            "\0\0\0\0\0\0\0",
            "asdfasdf\0\0aadsfasdfa\0",
            "\0\0អក្សរសាស្រ្តខែ្មរមានប្រវ៌ត្តជាងពីរពាន់ឆ្នាំមកហើយ",
    };

    @Before
    public void setUp() {
        Logger.getLogger("").setLevel(Level.INFO);
    }

    @Test
    public void testEstablishedMixedVersionSessionsAliceClientInitiated() throws OtrException {
        final Conversation c = new Conversation(2);

        // Prepare conversation with multiple clients.
        c.clientAlice.setPolicy(new OtrPolicy(ALLOW_V2 | ALLOW_V3 | ALLOW_V4));
        c.clientBob.setPolicy(new OtrPolicy(ALLOW_V3 | ALLOW_V4));
        final LinkedBlockingQueue<String> bob2Channel = new LinkedBlockingQueue<>(2);
        final Client bob2 = new Client("Bob 2", c.sessionIDBob, new OtrPolicy(ALLOW_V2 | ALLOW_V3), RANDOM, c.submitterAlice, bob2Channel);
        c.submitterBob.addQueue(bob2Channel);

        // Start setting up an encrypted session.
        c.clientAlice.session.startSession();
        // Expecting Query message from Alice.
        assertNull(c.clientBob.receiveMessage());
        assertNull(bob2.receiveMessage());
        // Expecting Identity message from Bob, DH-Commit message from Bob 2.
        assertNull(c.clientAlice.receiveMessage());
        assertNull(c.clientAlice.receiveMessage());
        // Expecting Auth-R message, DH-Key message from Alice.
        assertNull(c.clientBob.receiveMessage());
        assertEquals(ENCRYPTED, c.clientBob.session.getSessionStatus());
        assertEquals(Version.FOUR, c.clientBob.session.getOutgoingSession().getProtocolVersion());
        assertNull(c.clientBob.receiveMessage());
        assertNull(bob2.receiveMessage());
        assertNull(bob2.receiveMessage());
        // Expecting Auth-I message from Bob, Signature message from Bob 2.
        assertNull(c.clientAlice.receiveMessage());
        assertEquals(ENCRYPTED, c.clientAlice.session.getSessionStatus(c.clientBob.session.getSenderInstanceTag()));
        assertNull(c.clientAlice.receiveMessage());
        assertEquals(ENCRYPTED, c.clientAlice.session.getSessionStatus(bob2.session.getSenderInstanceTag()));
        // Expecting Reveal Signature message from Alice.
        assertNull(c.clientBob.receiveMessage());
        assertNull(bob2.receiveMessage());
        assertEquals(ENCRYPTED, bob2.session.getSessionStatus());
        assertEquals(Version.THREE, bob2.session.getOutgoingSession().getProtocolVersion());

        final String msg1 = "Hello Bob, this new IM software you installed on my PC the other day says we are talking Off-the-Record, what's that supposed to mean?";
        c.clientAlice.sendMessage(msg1);
        assertNotEquals(msg1, c.clientBob.receiptChannel.peek());
        assertNotEquals(msg1, bob2.receiptChannel.peek());
        assertEquals(msg1, c.clientBob.receiveMessage());
        assertNull(bob2.receiveMessage());
        c.clientAlice.session.setOutgoingSession(bob2.session.getSenderInstanceTag());
        c.clientAlice.sendMessage(msg1);
        assertNotEquals(msg1, c.clientBob.receiptChannel.peek());
        assertNotEquals(msg1, bob2.receiptChannel.peek());
        assertEquals(msg1, bob2.receiveMessage());
        assertNull(c.clientBob.receiveMessage());

        assertEquals(0, c.clientAlice.receiptChannel.size());
        assertEquals(0, c.clientBob.receiptChannel.size());
        assertEquals(0, bob2.receiptChannel.size());
    }

    @Test
    public void testEstablishedMixedVersionSessionsAliceClientInitiatedFragmented() throws OtrException, ProtocolException {
        final Conversation c = new Conversation(MAX_VALUE, 150);

        // Prepare conversation with multiple clients.
        c.clientAlice.setPolicy(new OtrPolicy(ALLOW_V2 | ALLOW_V3 | ALLOW_V4));
        c.clientBob.setPolicy(new OtrPolicy(ALLOW_V3 | ALLOW_V4));
        final LinkedBlockingQueue<String> bob2Channel = new LinkedBlockingQueue<>(MAX_VALUE);
        final Client bob2 = new Client("Bob 2", c.sessionIDBob, new OtrPolicy(ALLOW_V2 | ALLOW_V3), RANDOM, c.submitterAlice, bob2Channel);
        bob2.setMessageSize(150);
        c.submitterBob.addQueue(bob2Channel);

        // Start setting up an encrypted session.
        c.clientAlice.session.startSession();
        // Expecting Query message from Alice.
        rearrangeFragments(c.clientBob.receiptChannel, RANDOM);
        assertArrayEquals(new String[0], c.clientBob.receiveAllMessages(true));
        rearrangeFragments(bob2.receiptChannel, RANDOM);
        assertArrayEquals(new String[0], bob2.receiveAllMessages(true));
        // Expecting Identity message from Bob, DH-Commit message from Bob 2.
        rearrangeFragments(c.clientAlice.receiptChannel, RANDOM);
        assertArrayEquals(new String[0], c.clientAlice.receiveAllMessages(true));
        // Expecting Auth-R message, DH-Key message from Alice.
        rearrangeFragments(c.clientBob.receiptChannel, RANDOM);
        assertArrayEquals(new String[0], c.clientBob.receiveAllMessages(true));
        assertEquals(ENCRYPTED, c.clientBob.session.getSessionStatus());
        assertEquals(Session.Version.FOUR, c.clientBob.session.getOutgoingSession().getProtocolVersion());
        rearrangeFragments(bob2.receiptChannel, RANDOM);
        assertArrayEquals(new String[0], bob2.receiveAllMessages(true));
        // Expecting Auth-I message from Bob, Signature message from Bob 2.
        rearrangeFragments(c.clientAlice.receiptChannel, RANDOM);
        assertArrayEquals(new String[0], c.clientAlice.receiveAllMessages(true));
        assertEquals(ENCRYPTED, c.clientAlice.session.getSessionStatus(c.clientBob.session.getSenderInstanceTag()));
        assertEquals(ENCRYPTED, c.clientAlice.session.getSessionStatus(bob2.session.getSenderInstanceTag()));
        // Expecting DAKE data message, Reveal Signature message from Alice.
        rearrangeFragments(c.clientBob.receiptChannel, RANDOM);
        assertArrayEquals(new String[0], c.clientBob.receiveAllMessages(true));
        rearrangeFragments(bob2.receiptChannel, RANDOM);
        assertArrayEquals(new String[0], bob2.receiveAllMessages(true));
        assertEquals(ENCRYPTED, bob2.session.getSessionStatus());
        assertEquals(Session.Version.THREE, bob2.session.getOutgoingSession().getProtocolVersion());

        // Due to 2 sessions being set up at the same time, either one can be established first. The first session is
        // automatically chosen to be the default session, so we need to manually set our chosen session as default
        // outgoing session.
        c.clientAlice.session.setOutgoingSession(c.clientBob.session.getSenderInstanceTag());
        final String msg1 = "Hello Bob, this new IM software you installed on my PC the other day says we are talking Off-the-Record, what's that supposed to mean?";
        c.clientAlice.sendMessage(msg1);
        assertNotEquals(msg1, c.clientBob.receiptChannel.peek());
        assertNotEquals(msg1, bob2.receiptChannel.peek());
        rearrangeFragments(c.clientBob.receiptChannel, RANDOM);
        assertArrayEquals(new String[] {msg1}, c.clientBob.receiveAllMessages(true));
        rearrangeFragments(bob2.receiptChannel, RANDOM);
        assertArrayEquals(new String[0], bob2.receiveAllMessages(true));
        c.clientAlice.session.setOutgoingSession(bob2.session.getSenderInstanceTag());
        c.clientAlice.sendMessage(msg1);
        assertNotEquals(msg1, c.clientBob.receiptChannel.peek());
        assertNotEquals(msg1, bob2.receiptChannel.peek());
        rearrangeFragments(bob2.receiptChannel, RANDOM);
        assertArrayEquals(new String[] {msg1}, bob2.receiveAllMessages(true));
        rearrangeFragments(c.clientBob.receiptChannel, RANDOM);
        assertArrayEquals(new String[0], c.clientBob.receiveAllMessages(true));

        assertEquals(0, c.clientAlice.receiptChannel.size());
        assertEquals(0, c.clientBob.receiptChannel.size());
        assertEquals(0, bob2.receiptChannel.size());
    }

    @Test
    public void testEstablishedMixedVersionSessionsBobsClientInitiates() throws OtrException {
        final Conversation c = new Conversation(2);

        // Prepare conversation with multiple clients.
        c.clientAlice.setPolicy(new OtrPolicy(ALLOW_V2 | ALLOW_V3 | ALLOW_V4));
        c.clientBob.setPolicy(new OtrPolicy(ALLOW_V2 | ALLOW_V3));
        final LinkedBlockingQueue<String> bob2Channel = new LinkedBlockingQueue<>(2);
        final Client bob2 = new Client("Bob 2", c.sessionIDBob, new OtrPolicy(ALLOW_V3 | ALLOW_V4), RANDOM, c.submitterAlice, bob2Channel);
        c.submitterBob.addQueue(bob2Channel);

        // Start setting up an encrypted session.
        c.clientBob.sendMessage(OTRv23QueryMessage);
        assertNull(c.clientAlice.receiveMessage());
        // Expecting DH-Commit message from Alice.
        assertNull(c.clientBob.receiveMessage());
        assertNull(bob2.receiveMessage());
        // Expecting DH-Key message from both of Bob's clients.
        assertNull(c.clientAlice.receiveMessage());
        assertNull(c.clientAlice.receiveMessage());
        // Expecting Signature message from Alice.
        assertNull(c.clientBob.receiveMessage());
        assertNull(c.clientBob.receiveMessage());
        assertNull(bob2.receiveMessage());
        assertNull(bob2.receiveMessage());
        assertEquals(ENCRYPTED, c.clientBob.session.getSessionStatus());
        assertEquals(Session.Version.THREE, c.clientBob.session.getOutgoingSession().getProtocolVersion());
        assertEquals(ENCRYPTED, bob2.session.getSessionStatus());
        // TODO there is an issue with the OTR protocol such that acting on a received DH-Commit message skips the check of whether higher versions of the OTR protocol are available. (Consider not responding unless a query tag was previously sent.)
        assertEquals(Version.THREE, bob2.session.getOutgoingSession().getProtocolVersion());
        // Expecting Reveal Signature message from Bob.
        assertNull(c.clientAlice.receiveMessage());
        assertNull(c.clientAlice.receiveMessage());
        assertEquals(ENCRYPTED, c.clientAlice.session.getSessionStatus(c.clientBob.session.getSenderInstanceTag()));
        assertEquals(ENCRYPTED, c.clientAlice.session.getSessionStatus(bob2.session.getSenderInstanceTag()));

        final String msg1 = "Hello Bob, this new IM software you installed on my PC the other day says we are talking Off-the-Record, what's that supposed to mean?";
        c.clientAlice.sendMessage(msg1);
        assertNotEquals(msg1, c.clientBob.receiptChannel.peek());
        assertNotEquals(msg1, bob2.receiptChannel.peek());
        assertEquals(msg1, c.clientBob.receiveMessage());
        assertNull(bob2.receiveMessage());
    }

    @Test
    public void testMultipleSessions() throws OtrException {
        final OtrPolicy policy = new OtrPolicy(ALLOW_V2 | ALLOW_V3 | (OtrPolicy.ERROR_START_AKE & ~ALLOW_V4));
        final Conversation c = new Conversation(3);

        // Prepare conversation with multiple clients.
        c.clientAlice.setPolicy(policy);
        c.clientBob.setPolicy(policy);
        final LinkedBlockingQueue<String> bob2Channel = new LinkedBlockingQueue<>(3);
        final Client bob2 = new Client("Bob 2", c.sessionIDBob, policy, RANDOM, c.submitterAlice, bob2Channel);
        c.submitterBob.addQueue(bob2Channel);
        final LinkedBlockingQueue<String> bob3Channel = new LinkedBlockingQueue<>(3);
        final Client bob3 = new Client("Bob 3", c.sessionIDBob, policy, RANDOM, c.submitterAlice, bob3Channel);
        c.submitterBob.addQueue(bob3Channel);

        // Start setting up an encrypted session.
        c.clientBob.sendMessage(OTRv23QueryMessage);
        assertNull(c.clientAlice.receiveMessage());
        // Expecting DH-Commit message from Alice.
        assertNull(c.clientBob.receiveMessage());
        assertNull(bob2.receiveMessage());
        assertNull(bob3.receiveMessage());
        // Expecting DH-Key message from Bob.
        assertNull(c.clientAlice.receiveMessage());
        assertNull(c.clientAlice.receiveMessage());
        assertNull(c.clientAlice.receiveMessage());
        // Expecting Signature message from Alice.
        assertNull(c.clientBob.receiveMessage());
        assertNull(c.clientBob.receiveMessage());
        assertNull(c.clientBob.receiveMessage());
        assertNull(bob2.receiveMessage());
        assertNull(bob2.receiveMessage());
        assertNull(bob2.receiveMessage());
        assertNull(bob3.receiveMessage());
        assertNull(bob3.receiveMessage());
        assertNull(bob3.receiveMessage());
        assertEquals(ENCRYPTED, c.clientBob.session.getSessionStatus());
        assertEquals(ENCRYPTED, bob2.session.getSessionStatus());
        assertEquals(ENCRYPTED, bob3.session.getSessionStatus());
        // Expecting Reveal Signature message from Bob.
        assertNull(c.clientAlice.receiveMessage());
        assertNull(c.clientAlice.receiveMessage());
        assertNull(c.clientAlice.receiveMessage());
        assertEquals(ENCRYPTED, c.clientAlice.session.getSessionStatus(c.clientBob.session.getSenderInstanceTag()));
        assertEquals(ENCRYPTED, c.clientAlice.session.getSessionStatus(bob2.session.getSenderInstanceTag()));
        assertEquals(ENCRYPTED, c.clientAlice.session.getSessionStatus(bob3.session.getSenderInstanceTag()));

        final String msg1 = "Hello Bob, this new IM software you installed on my PC the other day says we are talking Off-the-Record, what's that supposed to mean?";
        c.clientAlice.sendMessage(msg1);
        assertNotEquals(msg1, c.clientBob.receiptChannel.peek());
        assertNotEquals(msg1, bob2.receiptChannel.peek());
        assertNotEquals(msg1, bob3.receiptChannel.peek());
        assertEquals(msg1, c.clientBob.receiveMessage());
        assertNull(bob2.receiveMessage());
        assertNull(bob3.receiveMessage());

        // Continue conversation with first of Bob's clients.
        final String msg2 = "Hey Alice, it means that our communication is encrypted and authenticated.";
        c.clientBob.sendMessage(msg2);
        assertNotEquals(msg2, c.clientAlice.receiptChannel.peek());
        assertEquals(msg2, c.clientAlice.receiveMessage());

        final String msg3 = "Oh, is that all?";
        c.clientAlice.sendMessage(msg3);
        assertNotEquals(msg3, c.clientBob.receiptChannel.peek());
        assertNotEquals(msg3, bob2.receiptChannel.peek());
        assertNotEquals(msg3, bob3.receiptChannel.peek());
        assertEquals(msg3, c.clientBob.receiveMessage());
        assertNull(bob2.receiveMessage());
        assertNull(bob3.receiveMessage());

        final String msg4 = "Actually no, our communication has the properties of perfect forward secrecy and deniable authentication.";
        c.clientBob.sendMessage(msg4);
        assertNotEquals(msg4, c.clientAlice.receiptChannel.peek());
        assertEquals(msg4, c.clientAlice.receiveMessage());

        final String msg5 = "Oh really?! pouvons-nous parler en français?";
        c.clientAlice.sendMessage(msg5);
        assertNotEquals(msg5, c.clientBob.receiptChannel.peek());
        assertNotEquals(msg5, bob2.receiptChannel.peek());
        assertNotEquals(msg5, bob3.receiptChannel.peek());
        assertEquals(msg5, c.clientBob.receiveMessage());
        assertNull(bob2.receiveMessage());
        assertNull(bob3.receiveMessage());
        assertEquals(ENCRYPTED, c.clientAlice.session.getSessionStatus());
        assertEquals(ENCRYPTED, c.clientBob.session.getSessionStatus());
        c.clientBob.session.endSession();
        assertEquals(ENCRYPTED, c.clientAlice.session.getSessionStatus());
        assertEquals(PLAINTEXT, c.clientBob.session.getSessionStatus());
        assertNull(c.clientAlice.receiveMessage());
        assertEquals(FINISHED, c.clientAlice.session.getSessionStatus());
        c.clientAlice.session.endSession();
        assertEquals(PLAINTEXT, c.clientAlice.session.getSessionStatus());
        assertEquals(PLAINTEXT, c.clientBob.session.getSessionStatus());
        assertEquals(ENCRYPTED, bob2.session.getSessionStatus());
        assertEquals(ENCRYPTED, bob3.session.getSessionStatus());

        assertEquals(0, c.clientAlice.receiptChannel.size());
        assertEquals(0, c.clientBob.receiptChannel.size());
        assertEquals(0, bob2.receiptChannel.size());
        assertEquals(0, bob3.receiptChannel.size());
    }

    @Test
    public void testQueryStart() throws OtrException {
        final Conversation c = new Conversation(1);
        c.clientAlice.setPolicy(new OtrPolicy(OPPORTUNISTIC & ~ALLOW_V4));
        c.clientBob.setPolicy(new OtrPolicy(OPPORTUNISTIC & ~ALLOW_V4));
        c.clientBob.sendMessage(OTRv23QueryMessage);
        assertNull(c.clientAlice.receiveMessage());
        // Expecting DH-Commit message from Alice.
        assertNull(c.clientBob.receiveMessage());
        // Expecting DH-Key message from Bob.
        assertNull(c.clientAlice.receiveMessage());
        // Expecting Signature message from Alice.
        assertNull(c.clientBob.receiveMessage());
        assertEquals(ENCRYPTED, c.clientBob.session.getSessionStatus());
        // Expecting Reveal Signature message from Bob.
        assertNull(c.clientAlice.receiveMessage());
        assertEquals(ENCRYPTED, c.clientAlice.session.getSessionStatus());
        final String msg1 = "Hello Bob, this new IM software you installed on my PC the other day says we are talking Off-the-Record, what's that supposed to mean?";
        c.clientAlice.sendMessage(msg1);
        assertNotEquals(msg1, c.clientBob.receiptChannel.peek());
        assertEquals(msg1, c.clientBob.receiveMessage());
        final String msg2 = "Hey Alice, it means that our communication is encrypted and authenticated.";
        c.clientBob.sendMessage(msg2);
        assertNotEquals(msg2, c.clientAlice.receiptChannel.peek());
        assertEquals(msg2, c.clientAlice.receiveMessage());
        final String msg3 = "Oh, is that all?";
        c.clientAlice.sendMessage(msg3);
        assertNotEquals(msg3, c.clientBob.receiptChannel.peek());
        assertEquals(msg3, c.clientBob.receiveMessage());
        final String msg4 = "Actually no, our communication has the properties of perfect forward secrecy and deniable authentication.";
        c.clientBob.sendMessage(msg4);
        assertNotEquals(msg4, c.clientAlice.receiptChannel.peek());
        assertEquals(msg4, c.clientAlice.receiveMessage());
        final String msg5 = "Oh really?! pouvons-nous parler en français?";
        c.clientAlice.sendMessage(msg5);
        assertNotEquals(msg5, c.clientBob.receiptChannel.peek());
        assertEquals(msg5, c.clientBob.receiveMessage());
        assertEquals(ENCRYPTED, c.clientAlice.session.getSessionStatus());
        assertEquals(ENCRYPTED, c.clientBob.session.getSessionStatus());
        c.clientBob.session.endSession();
        assertEquals(ENCRYPTED, c.clientAlice.session.getSessionStatus());
        // Bob has not yet switched session status as he has not processed the message yet.
        assertEquals(PLAINTEXT, c.clientBob.session.getSessionStatus());
        c.clientAlice.session.endSession();
        assertEquals(PLAINTEXT, c.clientAlice.session.getSessionStatus());
        assertEquals(PLAINTEXT, c.clientBob.session.getSessionStatus());
    }

    @Test
    public void testForcedStart() throws OtrException {
        final Conversation c = new Conversation(1);
        c.clientAlice.setPolicy(new OtrPolicy(OTRL_POLICY_MANUAL & ~ALLOW_V4));
        c.clientBob.setPolicy(new OtrPolicy(OTRL_POLICY_MANUAL & ~ALLOW_V4));
        c.clientBob.sendMessage("Hi Alice");
        assertEquals("Hi Alice", c.clientAlice.receiveMessage());
        // Initiate OTR by sending query message.
        c.clientAlice.session.startSession();
        assertNull(c.clientBob.receiveMessage());
        // Expecting DH-Commit message from Bob.
        assertNull(c.clientAlice.receiveMessage());
        // Expecting DH-Key message from Alice.
        assertNull(c.clientBob.receiveMessage());
        // Expecting Signature message from Bob.
        assertNull(c.clientAlice.receiveMessage());
        assertEquals(ENCRYPTED, c.clientAlice.session.getSessionStatus());
        // Expecting Reveal Signature message from Alice.
        assertNull(c.clientBob.receiveMessage());
        assertEquals(ENCRYPTED, c.clientBob.session.getSessionStatus());
        final String msg1 = "Hello Bob, this new IM software you installed on my PC the other day says we are talking Off-the-Record, what's that supposed to mean?";
        c.clientAlice.sendMessage(msg1);
        assertNotEquals(msg1, c.clientBob.receiptChannel.peek());
        assertEquals(msg1, c.clientBob.receiveMessage());
        final String msg2 = "Hey Alice, it means that our communication is encrypted and authenticated.";
        c.clientBob.sendMessage(msg2);
        assertNotEquals(msg2, c.clientAlice.receiptChannel.peek());
        assertEquals(msg2, c.clientAlice.receiveMessage());
        final String msg3 = "Oh, is that all?";
        c.clientAlice.sendMessage(msg3);
        assertNotEquals(msg3, c.clientBob.receiptChannel.peek());
        assertEquals(msg3, c.clientBob.receiveMessage());
        final String msg4 = "Actually no, our communication has the properties of perfect forward secrecy and deniable authentication.";
        c.clientBob.sendMessage(msg4);
        assertNotEquals(msg4, c.clientAlice.receiptChannel.peek());
        assertEquals(msg4, c.clientAlice.receiveMessage());
        final String msg5 = "Oh really?! pouvons-nous parler en français?";
        c.clientAlice.sendMessage(msg5);
        assertNotEquals(msg5, c.clientBob.receiptChannel.peek());
        assertEquals(msg5, c.clientBob.receiveMessage());
        assertEquals(ENCRYPTED, c.clientAlice.session.getSessionStatus());
        assertEquals(ENCRYPTED, c.clientBob.session.getSessionStatus());
        c.clientBob.session.endSession();
        assertEquals(ENCRYPTED, c.clientAlice.session.getSessionStatus());
        // Bob has not yet switched session status as he has not processed the message yet.
        assertEquals(PLAINTEXT, c.clientBob.session.getSessionStatus());
        c.clientAlice.session.endSession();
        assertEquals(PLAINTEXT, c.clientAlice.session.getSessionStatus());
        assertEquals(PLAINTEXT, c.clientBob.session.getSessionStatus());
    }

    @Test
    public void testPlaintext() throws OtrException {
        final Conversation c = new Conversation(1);
        final String msg1 = "Hello Bob, this new IM software you installed on my PC the other day says we are talking Off-the-Record, what's that supposed to mean?";
        c.clientAlice.sendMessage(msg1);
        assertEquals(msg1, c.clientBob.receiveMessage());
        assertEquals(PLAINTEXT, c.clientAlice.session.getSessionStatus());
        assertEquals(PLAINTEXT, c.clientBob.session.getSessionStatus());
        final String msg2 = "Hey Alice, it means that our communication is encrypted and authenticated.";
        c.clientBob.sendMessage(msg2);
        assertEquals(msg2, c.clientAlice.receiveMessage());
        assertEquals(PLAINTEXT, c.clientAlice.session.getSessionStatus());
        assertEquals(PLAINTEXT, c.clientBob.session.getSessionStatus());
        final String msg3 = "Oh, is that all?";
        c.clientAlice.sendMessage(msg3);
        assertEquals(msg3, c.clientBob.receiveMessage());
        assertEquals(PLAINTEXT, c.clientAlice.session.getSessionStatus());
        assertEquals(PLAINTEXT, c.clientBob.session.getSessionStatus());
        final String msg4 = "Actually no, our communication has the properties of perfect forward secrecy and deniable authentication.";
        c.clientBob.sendMessage(msg4);
        assertEquals(msg4, c.clientAlice.receiveMessage());
        assertEquals(PLAINTEXT, c.clientAlice.session.getSessionStatus());
        assertEquals(PLAINTEXT, c.clientBob.session.getSessionStatus());
        final String msg5 = "Oh really?! pouvons-nous parler en français?";
        c.clientAlice.sendMessage(msg5);
        assertEquals(msg5, c.clientBob.receiveMessage());
        assertEquals(PLAINTEXT, c.clientAlice.session.getSessionStatus());
        assertEquals(PLAINTEXT, c.clientBob.session.getSessionStatus());
        c.clientBob.session.endSession();
        c.clientAlice.session.endSession();
        assertEquals(PLAINTEXT, c.clientAlice.session.getSessionStatus());
        assertEquals(PLAINTEXT, c.clientBob.session.getSessionStatus());
    }

    @Test
    public void testPlainTextMessagingNewClients() throws OtrException {
        final Conversation c = new Conversation(1);
        c.clientBob.sendMessage("hello world");
        assertEquals("hello world", c.clientAlice.receiveMessage());
        c.clientAlice.sendMessage("hello bob");
        assertEquals("hello bob", c.clientBob.receiveMessage());
    }

    @Test
    public void testUnicodeMessagesInPlainTextSession() throws OtrException {
        final Conversation c = new Conversation(2);
        for (final String message : UNICODE_LINES) {
            assertEquals(SessionStatus.PLAINTEXT, c.clientAlice.session.getSessionStatus());
            c.clientAlice.sendMessage(message);
            assertEquals(message, c.clientBob.receiptChannel.peek());
            final String receivedBob = c.clientBob.receiveMessage();
            assertEquals(SessionStatus.PLAINTEXT, c.clientBob.session.getSessionStatus());
            assertEquals(message, receivedBob);

            assertEquals(SessionStatus.PLAINTEXT, c.clientBob.session.getSessionStatus());
            c.clientBob.sendMessage(message);
            assertEquals(message, c.clientAlice.receiptChannel.peek());
            final String receivedAlice = c.clientAlice.receiveMessage();
            assertEquals(SessionStatus.PLAINTEXT, c.clientAlice.session.getSessionStatus());
            assertEquals(message, receivedAlice);
        }
    }

    @Test
    public void testNullLinesInPlainTextSession() throws OtrException {
        final Conversation c = new Conversation(2);
        for (final String line : NULL_LINES) {
            assertEquals(SessionStatus.PLAINTEXT, c.clientAlice.session.getSessionStatus());
            c.clientAlice.sendMessage(line);
            assertEquals(line, c.clientBob.receiptChannel.peek());
            final String receivedBob = c.clientBob.receiveMessage();
            assertEquals(SessionStatus.PLAINTEXT, c.clientBob.session.getSessionStatus());
            assertEquals(line, receivedBob);

            assertEquals(SessionStatus.PLAINTEXT, c.clientBob.session.getSessionStatus());
            c.clientBob.sendMessage(line);
            assertEquals(line, c.clientAlice.receiptChannel.peek());
            final String receivedAlice = c.clientAlice.receiveMessage();
            assertEquals(SessionStatus.PLAINTEXT, c.clientAlice.session.getSessionStatus());
            assertEquals(line, receivedAlice);
        }
    }

    @Test
    public void testNullLinesInEncryptedSession() throws OtrException {
        final Conversation c = new Conversation(2);
        c.clientAlice.setPolicy(new OtrPolicy(OtrPolicy.ALLOW_V4));
        c.clientBob.setPolicy(new OtrPolicy(OtrPolicy.ALLOW_V4));
        c.clientAlice.session.startSession();
        c.clientBob.receiveMessage();
        c.clientAlice.receiveMessage();
        c.clientBob.receiveMessage();
        assertEquals(SessionStatus.ENCRYPTED, c.clientBob.session.getSessionStatus());
        c.clientAlice.receiveMessage();
        assertEquals(SessionStatus.ENCRYPTED, c.clientAlice.session.getSessionStatus());
        for (final String line : NULL_LINES) {
            c.clientAlice.sendMessage(line);
            final String sanitizedLine = line.replace('\0', '?');
            assertNotEquals(sanitizedLine, c.clientBob.receiptChannel.peek());
            final String receivedBob = c.clientBob.receiveMessage();
            assertEquals(SessionStatus.ENCRYPTED, c.clientBob.session.getSessionStatus());
            assertEquals(sanitizedLine, receivedBob);

            c.clientBob.sendMessage(line);
            assertNotEquals(sanitizedLine, c.clientAlice.receiptChannel.peek());
            final String receivedAlice = c.clientAlice.receiveMessage();
            assertEquals(SessionStatus.ENCRYPTED, c.clientAlice.session.getSessionStatus());
            assertEquals(sanitizedLine, receivedAlice);
        }
    }

    @Test
    public void testUnicodeMessagesInEncryptedSession() throws OtrException {
        final Conversation c = new Conversation(2);
        c.clientAlice.setPolicy(new OtrPolicy(OtrPolicy.ALLOW_V4));
        c.clientBob.setPolicy(new OtrPolicy(OtrPolicy.ALLOW_V4));
        c.clientAlice.session.startSession();
        c.clientBob.receiveMessage();
        c.clientAlice.receiveMessage();
        c.clientBob.receiveMessage();
        assertEquals(SessionStatus.ENCRYPTED, c.clientBob.session.getSessionStatus());
        c.clientAlice.receiveMessage();
        assertEquals(SessionStatus.ENCRYPTED, c.clientAlice.session.getSessionStatus());
        for (final String message : UNICODE_LINES) {
            c.clientAlice.sendMessage(message);
            assertNotEquals(message, c.clientBob.receiptChannel.peek());
            final String receivedBob = c.clientBob.receiveMessage();
            assertEquals(SessionStatus.ENCRYPTED, c.clientBob.session.getSessionStatus());
            assertEquals(message, receivedBob);

            assertEquals(SessionStatus.ENCRYPTED, c.clientBob.session.getSessionStatus());
            c.clientBob.sendMessage(message);
            assertNotEquals(message, c.clientAlice.receiptChannel.peek());
            final String receivedAlice = c.clientAlice.receiveMessage();
            assertEquals(SessionStatus.ENCRYPTED, c.clientAlice.session.getSessionStatus());
            assertEquals(message, receivedAlice);
        }
        c.clientBob.session.endSession();
        assertEquals(SessionStatus.PLAINTEXT, c.clientBob.session.getSessionStatus());
        c.clientAlice.receiveMessage();
        assertEquals(SessionStatus.FINISHED, c.clientAlice.session.getSessionStatus());
        c.clientAlice.session.endSession();
        assertEquals(SessionStatus.PLAINTEXT, c.clientAlice.session.getSessionStatus());
    }

    @Test
    public void testEstablishOTR4Session() throws OtrException {
        final Conversation c = new Conversation(1);
        c.clientBob.sendMessage("Hi Alice");
        assertEquals("Hi Alice", c.clientAlice.receiveMessage());
        // Initiate OTR by sending query message.
        c.clientAlice.session.startSession();
        assertNull(c.clientBob.receiveMessage());
        // Expecting Identity message from Bob.
        assertNull(c.clientAlice.receiveMessage());
        // Expecting AUTH_R message from Alice.
        assertNull(c.clientBob.receiveMessage());
        assertEquals(ENCRYPTED, c.clientBob.session.getSessionStatus());
        // Expecting AUTH_I message from Bob.
        assertNull(c.clientAlice.receiveMessage());
        assertEquals(ENCRYPTED, c.clientAlice.session.getSessionStatus());
        // Start sending messages
        c.clientBob.sendMessage("Hello Alice!");
        assertNotEquals("Hello Alice!", c.clientAlice.receiptChannel.peek());
        assertEquals("Hello Alice!", c.clientAlice.receiveMessage());
        c.clientAlice.session.endSession();
        assertEquals(PLAINTEXT, c.clientAlice.session.getSessionStatus());
        assertEquals(ENCRYPTED, c.clientBob.session.getSessionStatus());
        assertNull(c.clientBob.receiveMessage());
        assertEquals(FINISHED, c.clientBob.session.getSessionStatus());
    }

    // TODO make this test work once Double Ratchet algorithm is redesigned.
    @Ignore("As of yet unsupported use case. Depends on redesign of Double Ratchet algorithm.")
    @Test
    public void testEstablishOTR4SessionEarlyMessaging() throws OtrException {
        final Conversation c = new Conversation(3);
        c.clientBob.sendMessage("Hi Alice");
        assertEquals("Hi Alice", c.clientAlice.receiveMessage());
        // Initiate OTR by sending query message.
        c.clientAlice.session.startSession();
        assertNull(c.clientBob.receiveMessage());
        // Expecting Identity message from Bob.
        assertNull(c.clientAlice.receiveMessage());
        // Expecting AUTH_R message from Alice.
        assertNull(c.clientBob.receiveMessage());
        assertEquals(ENCRYPTED, c.clientBob.session.getSessionStatus());
        c.clientBob.sendMessage("Bob's early message 1");
        c.clientBob.sendMessage("Bob's early message 2");
        // Expecting AUTH_I message from Bob.
        assertNull(c.clientAlice.receiveMessage());
        assertEquals(ENCRYPTED, c.clientAlice.session.getSessionStatus());
        c.clientAlice.sendMessage("Alice's early message 1");
        c.clientAlice.sendMessage("Alice's early message 2");
        // Start sending messages
        assertEquals("Bob's early message 1", c.clientAlice.receiveMessage());
        assertEquals("Bob's early message 2", c.clientAlice.receiveMessage());
        assertEquals("Alice's early message 1", c.clientBob.receiveMessage());
        assertEquals("Alice's early message 2", c.clientBob.receiveMessage());
        c.clientBob.sendMessage("Hello Alice, I got your messages.");
        assertEquals("Hello Alice, I got your messages.", c.clientAlice.receiveMessage());
        assertEquals(0, c.clientBob.receiptChannel.size());
        assertEquals(0, c.clientAlice.receiptChannel.size());
        c.clientAlice.session.endSession();
        assertEquals(PLAINTEXT, c.clientAlice.session.getSessionStatus());
        assertEquals(ENCRYPTED, c.clientBob.session.getSessionStatus());
        assertNull(c.clientBob.receiveMessage());
        assertEquals(FINISHED, c.clientBob.session.getSessionStatus());
    }

    // TODO make this test work once Double Ratchet algorithm is redesigned.
    @Ignore("As of yet unsupported use case. Depends on redesign of Double Ratchet algorithm.")
    @Test
    public void testEstablishOTR4SessionEarlyMessagingOutOfOrder() throws OtrException {
        final Conversation c = new Conversation(3);
        c.clientBob.sendMessage("Hi Alice");
        assertEquals("Hi Alice", c.clientAlice.receiveMessage());
        // Initiate OTR by sending query message.
        c.clientAlice.session.startSession();
        assertNull(c.clientBob.receiveMessage());
        // Expecting Identity message from Bob.
        assertNull(c.clientAlice.receiveMessage());
        // Expecting AUTH_R message from Alice.
        assertNull(c.clientBob.receiveMessage());
        assertEquals(ENCRYPTED, c.clientBob.session.getSessionStatus());
        c.clientBob.sendMessage("Bob's early message 1");
        c.clientBob.sendMessage("Bob's early message 2");

        // Expecting AUTH_I message from Bob.
        assertNull(c.clientAlice.receiveMessage());
        assertEquals(ENCRYPTED, c.clientAlice.session.getSessionStatus());
        c.clientAlice.sendMessage("Alice's early message 1");
        c.clientAlice.sendMessage("Alice's early message 2");
        // Receive messages out-of-order.
        c.clientAlice.receiptChannel.add(c.clientAlice.receiptChannel.remove());
        assertEquals("Bob's early message 2", c.clientAlice.receiveMessage());
        assertEquals("Bob's early message 1", c.clientAlice.receiveMessage());
        c.clientBob.receiptChannel.add(c.clientBob.receiptChannel.remove());
        assertEquals("Alice's early message 2", c.clientBob.receiveMessage());
        assertEquals("Alice's early message 1", c.clientBob.receiveMessage());
        c.clientBob.sendMessage("Hello Alice, I got your messages.");
        assertEquals("Hello Alice, I got your messages.", c.clientAlice.receiveMessage());
        assertEquals(0, c.clientBob.receiptChannel.size());
        assertEquals(0, c.clientAlice.receiptChannel.size());
        c.clientAlice.session.endSession();
        assertEquals(PLAINTEXT, c.clientAlice.session.getSessionStatus());
        assertEquals(ENCRYPTED, c.clientBob.session.getSessionStatus());
        assertNull(c.clientBob.receiveMessage());
        assertEquals(FINISHED, c.clientBob.session.getSessionStatus());
    }

    @Test
    public void testEstablishOTR4SessionThenDisallowSendingQueryMessage() throws OtrException {
        final Conversation c = new Conversation(1);
        c.clientBob.sendMessage("Hi Alice");
        assertEquals("Hi Alice", c.clientAlice.receiveMessage());
        // Initiate OTR by sending query message.
        c.clientAlice.session.startSession();
        assertNull(c.clientBob.receiveMessage());
        // Expecting Identity message from Bob.
        assertNull(c.clientAlice.receiveMessage());
        // Expecting AUTH_R message from Alice.
        assertNull(c.clientBob.receiveMessage());
        assertEquals(ENCRYPTED, c.clientBob.session.getSessionStatus());
        // Expecting AUTH_I message from Bob.
        assertNull(c.clientAlice.receiveMessage());
        assertEquals(ENCRYPTED, c.clientAlice.session.getSessionStatus());
        // Start sending messages
        c.clientBob.sendMessage("Hello Alice!");
        assertNotEquals("Hello Alice!", c.clientAlice.receiptChannel.peek());
        assertEquals("Hello Alice!", c.clientAlice.receiveMessage());
        // Even though encrypted now, start a new session. This should not follow through.
        c.clientBob.session.startSession();
        assertTrue(c.clientAlice.receiptChannel.isEmpty());
        assertEquals(ENCRYPTED, c.clientBob.session.getSessionStatus());
        assertEquals(ENCRYPTED, c.clientAlice.session.getSessionStatus());
        c.clientAlice.session.endSession();
        assertEquals(PLAINTEXT, c.clientAlice.session.getSessionStatus());
        assertEquals(ENCRYPTED, c.clientBob.session.getSessionStatus());
        assertNull(c.clientBob.receiveMessage());
        assertEquals(FINISHED, c.clientBob.session.getSessionStatus());
    }

    @Test
    public void testEstablishOTR4SessionFragmented() throws OtrException {
        final Conversation c = new Conversation(21, 150);
        c.clientBob.sendMessage("Hi Alice");
        assertEquals("Hi Alice", c.clientAlice.receiveMessage());
        // Initiate OTR by sending query message.
        c.clientAlice.session.startSession();
        assertNull(c.clientBob.receiveMessage());
        // Expecting Identity message from Bob.
        assertArrayEquals(new String[0], c.clientAlice.receiveAllMessages(true));
        // Expecting AUTH_R message from Alice.
        assertArrayEquals(new String[0], c.clientBob.receiveAllMessages(true));
        assertEquals(ENCRYPTED, c.clientBob.session.getSessionStatus());
        // Expecting AUTH_I message from Bob.
        assertArrayEquals(new String[0], c.clientAlice.receiveAllMessages(true));
        assertEquals(ENCRYPTED, c.clientAlice.session.getSessionStatus());
    }

    @Test
    public void testEstablishOTR4SessionFragmentedMessageFragmentDropped() throws OtrException {
        final Conversation c = new Conversation(21, 150);
        c.clientBob.sendMessage("Hi Alice");
        assertEquals("Hi Alice", c.clientAlice.receiveMessage());
        // Initiate OTR by sending query message.
        c.clientAlice.session.startSession();
        assertNull(c.clientBob.receiveMessage());
        // Expecting Identity message from Bob.
        assertArrayEquals(new String[0], c.clientAlice.receiveAllMessages(true));
        // Expecting AUTH_R message from Alice.
        assertArrayEquals(new String[0], c.clientBob.receiveAllMessages(true));
        assertEquals(ENCRYPTED, c.clientBob.session.getSessionStatus());
        // Expecting AUTH_I message from Bob.
        assertArrayEquals(new String[0], c.clientAlice.receiveAllMessages(true));
        assertEquals(ENCRYPTED, c.clientAlice.session.getSessionStatus());
        assertTrue(c.clientAlice.receiptChannel.isEmpty());
        assertTrue(c.clientBob.receiptChannel.isEmpty());
        c.clientAlice.sendMessage("Hello Bob!");
        assertNotEquals("Hello Bob!", c.clientBob.receiptChannel.peek());
        assertArrayEquals(new String[] {"Hello Bob!"}, c.clientBob.receiveAllMessages(true));
        c.clientAlice.sendMessage("Hello Bob - this messages gets partially dropped ............................");
        drop(new int[] {RANDOM.nextInt(4)}, c.clientBob.receiptChannel);
        c.clientAlice.sendMessage("You should be able to receive this message.");
        assertArrayEquals(new String[] {"You should be able to receive this message."}, c.clientBob.receiveAllMessages(true));
    }

    @Test
    public void testOTR4ExtensiveMessagingToVerifyRatcheting() throws OtrException {
        final Conversation c = new Conversation(1);
        c.clientBob.sendMessage("Hi Alice");
        assertEquals("Hi Alice", c.clientAlice.receiveMessage());
        // Initiate OTR by sending query message.
        c.clientAlice.session.startSession();
        assertNull(c.clientBob.receiveMessage());
        // Expecting Identity message from Bob.
        assertNull(c.clientAlice.receiveMessage());
        // Expecting AUTH_R message from Alice.
        assertNull(c.clientBob.receiveMessage());
        assertEquals(ENCRYPTED, c.clientBob.session.getSessionStatus());
        // Expecting AUTH_I message from Bob.
        assertNull(c.clientAlice.receiveMessage());
        assertEquals(ENCRYPTED, c.clientAlice.session.getSessionStatus());

        for (int i = 0; i < 25; i++) {
            // Bob sending a message (alternating, to enable ratchet)
            final String messageBob = randomMessage(300);
            c.clientBob.sendMessage(messageBob);
            assertMessage("Iteration: " + i + ", message Bob: " + messageBob, messageBob, c.clientAlice.receiveMessage());
            // Alice sending a message (alternating, to enable ratchet)
            final String messageAlice = randomMessage(300);
            c.clientAlice.sendMessage(messageAlice);
            assertMessage("Iteration: " + i + ", message Alice: " + messageAlice, messageAlice, c.clientBob.receiveMessage());
        }
    }

    @Test
    public void testOTR4ExtensiveMessagingToVerifyRatchetingManyConsecutiveMessages() throws OtrException {
        final Conversation c = new Conversation(25);
        c.clientBob.sendMessage("Hi Alice");
        assertEquals("Hi Alice", c.clientAlice.receiveMessage());
        // Initiate OTR by sending query message.
        c.clientAlice.session.startSession();
        assertNull(c.clientBob.receiveMessage());
        // Expecting Identity message from Bob.
        assertNull(c.clientAlice.receiveMessage());
        // Expecting AUTH_R message from Alice.
        assertNull(c.clientBob.receiveMessage());
        assertEquals(ENCRYPTED, c.clientBob.session.getSessionStatus());
        // Expecting AUTH_I message from Bob.
        assertNull(c.clientAlice.receiveMessage());
        assertEquals(ENCRYPTED, c.clientAlice.session.getSessionStatus());

        final String[] messages = new String[25];
        for (int i = 0; i < messages.length; i++) {
            messages[i] = randomMessage(300);
        }
        // Bob sending many messages
        for (final String message : messages) {
            c.clientBob.sendMessage(message);
        }
        for (final String message : messages) {
            assertMessage("Message Bob: " + message, message, c.clientAlice.receiveMessage());
        }
        // Alice sending one message in response
        final String messageAlice = "Man, you talk a lot!";
        c.clientAlice.sendMessage(messageAlice);
        assertMessage("Message Alice: " + messageAlice, messageAlice, c.clientBob.receiveMessage());
    }

    @Test
    public void testOTR4ExtensiveMessagingManyConsecutiveMessagesIncidentallyDropped() throws OtrException {
        final Conversation c = new Conversation(25);
        c.clientBob.sendMessage("Hi Alice");
        assertEquals("Hi Alice", c.clientAlice.receiveMessage());
        // Initiate OTR by sending query message.
        c.clientAlice.session.startSession();
        assertNull(c.clientBob.receiveMessage());
        // Expecting Identity message from Bob.
        assertNull(c.clientAlice.receiveMessage());
        // Expecting AUTH_R message from Alice.
        assertNull(c.clientBob.receiveMessage());
        assertEquals(ENCRYPTED, c.clientBob.session.getSessionStatus());
        // Expecting AUTH_I message from Bob.
        assertNull(c.clientAlice.receiveMessage());
        assertEquals(ENCRYPTED, c.clientAlice.session.getSessionStatus());

        final String[] messages = new String[25];
        for (int i = 0; i < messages.length; i++) {
            messages[i] = randomMessage(300);
        }
        // Bob sending many messages
        for (final String message : messages) {
            c.clientBob.sendMessage(message);
        }
        // Determine three messages to drop. Avoid dropping first message as this is a known limitation that cannot be
        // mitigated.
        final int drop1 = RANDOM.nextInt(messages.length - 1) + 1;
        final int drop2 = RANDOM.nextInt(messages.length - 1) + 1;
        final int drop3 = RANDOM.nextInt(messages.length - 1) + 1;
        drop(new int[] {drop1, drop2, drop3}, c.clientAlice.receiptChannel);
        for (int i = 0; i < messages.length; i++) {
            if (i == drop1 || i == drop2 || i == drop3) {
                continue;
            }
            assertMessage("Message Bob: " + messages[i], messages[i], c.clientAlice.receiveMessage());
        }
        // Alice sending one message in response
        final String messageAlice = "Man, you talk a lot!";
        c.clientAlice.sendMessage(messageAlice);
        assertMessage("Message Alice: " + messageAlice, messageAlice, c.clientBob.receiveMessage());
    }

    @Ignore("Test demonstrates support for out-of-order messages and specifically messages that arrive later than expected. This is not yet supported in the library. We need to store message keys for later look-back to make this test work.")
    @Test
    public void testOTR4ExtensiveMessagingManyConsecutiveMessagesShuffled() throws OtrException {
        final Conversation c = new Conversation(25);
        c.clientBob.sendMessage("Hi Alice");
        assertEquals("Hi Alice", c.clientAlice.receiveMessage());
        // Initiate OTR by sending query message.
        c.clientAlice.session.startSession();
        assertNull(c.clientBob.receiveMessage());
        // Expecting Identity message from Bob.
        assertNull(c.clientAlice.receiveMessage());
        // Expecting AUTH_R message from Alice.
        assertNull(c.clientBob.receiveMessage());
        assertEquals(ENCRYPTED, c.clientBob.session.getSessionStatus());
        // Expecting AUTH_I message from Bob.
        assertNull(c.clientAlice.receiveMessage());
        assertEquals(ENCRYPTED, c.clientAlice.session.getSessionStatus());

        final String[] messages = new String[25];
        for (int i = 0; i < messages.length; i++) {
            messages[i] = randomMessage(300);
        }
        // Bob sending many messages
        for (final String message : messages) {
            c.clientBob.sendMessage(message);
        }
        shuffle(c.clientAlice.receiptChannel, RANDOM);
        final HashSet<String> receivedMessages = new HashSet<>();
        for (int i = 0; i < messages.length; i++) {
            final String received = c.clientAlice.receiveMessage();
            if (!contains(received, messages)) {
                fail("Expected message to be present in the list of sent messages: " + received);
            }
            receivedMessages.add(received);
        }
        assertEquals(messages.length, receivedMessages.size());
        // Alice sending one message in response
        final String messageAlice = "Man, you talk a lot!";
        c.clientAlice.sendMessage(messageAlice);
        assertMessage("Message Alice: " + messageAlice, messageAlice, c.clientBob.receiveMessage());
        c.clientAlice.session.endSession();
        c.clientBob.session.endSession();
    }

    @Test
    public void testOTR4SessionWithSMPGoodPassword() throws OtrException {
        final Conversation c = new Conversation(1);

        assertTrue(c.clientAlice.verified.isEmpty());
        assertTrue(c.clientBob.verified.isEmpty());

        // Initiate OTR by sending query message.
        c.clientAlice.session.startSession();
        assertNull(c.clientBob.receiveMessage());
        // Expecting Identity message from Bob.
        assertNull(c.clientAlice.receiveMessage());
        // Expecting AUTH_R message from Alice.
        assertNull(c.clientBob.receiveMessage());
        assertEquals(ENCRYPTED, c.clientBob.session.getSessionStatus());
        // Expecting AUTH_I message from Bob.
        assertNull(c.clientAlice.receiveMessage());
        assertEquals(ENCRYPTED, c.clientAlice.session.getSessionStatus());

        // Initiate SMP negotiation
        assertFalse(c.clientBob.session.isSmpInProgress());
        assertFalse(c.clientAlice.session.isSmpInProgress());
        c.clientBob.session.initSmp("What's the secret?", "Nobody knows!");
        assertTrue(c.clientBob.session.isSmpInProgress());
        assertFalse(c.clientAlice.session.isSmpInProgress());

        assertNull(c.clientAlice.receiveMessage());
        c.clientAlice.session.respondSmp("What's the secret?", "Nobody knows!");
        assertTrue(c.clientBob.session.isSmpInProgress());
        assertTrue(c.clientAlice.session.isSmpInProgress());

        assertNull(c.clientBob.receiveMessage());
        assertTrue(c.clientBob.session.isSmpInProgress());
        assertTrue(c.clientAlice.session.isSmpInProgress());

        assertNull(c.clientAlice.receiveMessage());
        assertTrue(c.clientBob.session.isSmpInProgress());
        assertFalse(c.clientAlice.session.isSmpInProgress());

        assertNull(c.clientBob.receiveMessage());
        assertFalse(c.clientBob.session.isSmpInProgress());
        assertFalse(c.clientAlice.session.isSmpInProgress());

        assertEquals(1, c.clientAlice.verified.size());
        assertEquals(1, c.clientBob.verified.size());
    }

    @Test
    public void testOTR4SessionWithSMPBadPassword() throws OtrException {
        final Conversation c = new Conversation(1);

        assertTrue(c.clientAlice.verified.isEmpty());
        assertTrue(c.clientBob.verified.isEmpty());

        // Initiate OTR by sending query message.
        c.clientAlice.session.startSession();
        assertNull(c.clientBob.receiveMessage());
        // Expecting Identity message from Bob.
        assertNull(c.clientAlice.receiveMessage());
        // Expecting AUTH_R message from Alice.
        assertNull(c.clientBob.receiveMessage());
        assertEquals(ENCRYPTED, c.clientBob.session.getSessionStatus());
        // Expecting AUTH_I message from Bob.
        assertNull(c.clientAlice.receiveMessage());
        assertEquals(ENCRYPTED, c.clientAlice.session.getSessionStatus());

        // Initiate SMP negotiation
        c.clientBob.session.initSmp("What's the secret?", "Nobody knows!");
        assertTrue(c.clientBob.session.isSmpInProgress());
        assertNull(c.clientAlice.receiveMessage());
        c.clientAlice.session.respondSmp("What's the secret?", "Everybody knows!");
        assertTrue(c.clientAlice.session.isSmpInProgress());
        assertNull(c.clientBob.receiveMessage());
        assertTrue(c.clientAlice.session.isSmpInProgress());
        assertNull(c.clientAlice.receiveMessage());
        assertFalse(c.clientAlice.session.isSmpInProgress());
        assertTrue(c.clientBob.session.isSmpInProgress());
        assertNull(c.clientBob.receiveMessage());
        assertFalse(c.clientBob.session.isSmpInProgress());

        assertTrue(c.clientAlice.verified.isEmpty());
        assertTrue(c.clientBob.verified.isEmpty());
    }

    @Test
    public void testOTR4SessionWithSMPUnicodeTests() throws OtrException {
        final Conversation c = new Conversation(1);
        // Initiate OTR by sending query message.
        c.clientAlice.session.startSession();
        assertNull(c.clientBob.receiveMessage());
        // Expecting Identity message from Bob.
        assertNull(c.clientAlice.receiveMessage());
        // Expecting AUTH_R message from Alice.
        assertNull(c.clientBob.receiveMessage());
        assertEquals(ENCRYPTED, c.clientBob.session.getSessionStatus());
        // Expecting AUTH_I message from Bob.
        assertNull(c.clientAlice.receiveMessage());
        assertEquals(ENCRYPTED, c.clientAlice.session.getSessionStatus());

        for (int i = 0; i < UNICODE_LINES.length; ++i) {
            c.clientBob.verified.clear();
            c.clientAlice.verified.clear();

            // Initiate SMP negotiation
            c.clientBob.session.initSmp(UNICODE_LINES[i], UNICODE_LINES[UNICODE_LINES.length - 1 - i]);
            assertTrue(c.clientBob.session.isSmpInProgress());
            assertNull(c.clientAlice.receiveMessage());
            c.clientAlice.session.respondSmp(UNICODE_LINES[i], UNICODE_LINES[UNICODE_LINES.length - 1 - i]);
            assertTrue(c.clientAlice.session.isSmpInProgress());
            assertNull(c.clientBob.receiveMessage());
            assertTrue(c.clientAlice.session.isSmpInProgress());
            assertNull(c.clientAlice.receiveMessage());
            assertFalse(c.clientAlice.session.isSmpInProgress());
            assertTrue(c.clientBob.session.isSmpInProgress());
            assertNull(c.clientBob.receiveMessage());
            assertFalse(c.clientBob.session.isSmpInProgress());

            assertEquals(1, c.clientBob.verified.size());
            assertEquals(1, c.clientAlice.verified.size());
        }
    }

    @Test
    public void testOTR4ExtensiveMessagingFragmentation() throws OtrException {
        final Conversation c = new Conversation(21, 150);
        c.clientBob.sendMessage("Hi Alice");
        assertEquals("Hi Alice", c.clientAlice.receiveMessage());
        // Initiate OTR by sending query message.
        c.clientAlice.session.startSession();
        assertNull(c.clientBob.receiveMessage());
        // Expecting Identity message from Bob.
        assertArrayEquals(new String[0], c.clientAlice.receiveAllMessages(true));
        // Expecting AUTH_R message from Alice.
        assertArrayEquals(new String[0], c.clientBob.receiveAllMessages(true));
        assertEquals(ENCRYPTED, c.clientBob.session.getSessionStatus());
        // Expecting AUTH_I message from Bob.
        assertArrayEquals(new String[0], c.clientAlice.receiveAllMessages(true));
        assertEquals(ENCRYPTED, c.clientAlice.session.getSessionStatus());

        for (int i = 0; i < 25; i++) {
            // Bob sending a message (alternating, to enable ratchet)
            final String messageBob = randomMessage(1, 500);
            c.clientBob.sendMessage(messageBob);
            assertArrayEquals("Iteration: " + i + ", message Bob: " + messageBob,
                    new String[] {messageBob}, c.clientAlice.receiveAllMessages(true));
            // Alice sending a message (alternating, to enable ratchet)
            final String messageAlice = randomMessage(1, 500);
            c.clientAlice.sendMessage(messageAlice);
            assertArrayEquals("Iteration: " + i + ", message Alice: " + messageAlice,
                    new String[] {messageAlice}, c.clientBob.receiveAllMessages(true));
        }
    }

    @Test
    public void testOTR4ExtensiveMessagingFragmentationShuffled() throws OtrException {
        final Conversation c = new Conversation(21, 150);
        c.clientBob.sendMessage("Hi Alice");
        assertEquals("Hi Alice", c.clientAlice.receiveMessage());
        // Initiate OTR by sending query message.
        c.clientAlice.session.startSession();
        assertNull(c.clientBob.receiveMessage());
        // Expecting Identity message from Bob.
        shuffle(c.clientAlice.receiptChannel, RANDOM);
        assertArrayEquals(new String[0], c.clientAlice.receiveAllMessages(true));
        // Expecting AUTH_R message from Alice.
        shuffle(c.clientBob.receiptChannel, RANDOM);
        assertArrayEquals(new String[0], c.clientBob.receiveAllMessages(true));
        assertEquals(ENCRYPTED, c.clientBob.session.getSessionStatus());
        // Expecting AUTH_I message from Bob.
        shuffle(c.clientAlice.receiptChannel, RANDOM);
        assertArrayEquals(new String[0], c.clientAlice.receiveAllMessages(true));
        assertEquals(ENCRYPTED, c.clientAlice.session.getSessionStatus());
        // Expecting heartbeat message from Alice to enable Bob to complete the Double Ratchet initialization.
        shuffle(c.clientBob.receiptChannel, RANDOM);
        assertEquals(0, c.clientBob.receiveAllMessages(true).length);

        for (int i = 0; i < 25; i++) {
            // Bob sending a message (alternating, to enable ratchet)
            final String messageBob = randomMessage(1, 500);
            c.clientBob.sendMessage(messageBob);
            shuffle(c.clientAlice.receiptChannel, RANDOM);
            assertArrayEquals("Iteration: " + i + ", message Bob: " + messageBob,
                    new String[] {messageBob}, c.clientAlice.receiveAllMessages(true));
            // Alice sending a message (alternating, to enable ratchet)
            final String messageAlice = randomMessage(1, 500);
            c.clientAlice.sendMessage(messageAlice);
            shuffle(c.clientBob.receiptChannel, RANDOM);
            assertArrayEquals("Iteration: " + i + ", message Alice: " + messageAlice,
                    new String[] {messageAlice}, c.clientBob.receiveAllMessages(true));
        }
    }

    @Test
    public void testOTR4SmallConversationWithHugeMessages() throws OtrException {
        final Conversation c = new Conversation(1);
        c.clientBob.sendMessage("Hi Alice");
        assertEquals("Hi Alice", c.clientAlice.receiveMessage());
        // Initiate OTR by sending query message.
        c.clientAlice.session.startSession();
        assertNull(c.clientBob.receiveMessage());
        // Expecting Identity message from Bob.
        assertNull(c.clientAlice.receiveMessage());
        // Expecting AUTH_R message from Alice.
        assertNull(c.clientBob.receiveMessage());
        assertEquals(ENCRYPTED, c.clientBob.session.getSessionStatus());
        // Expecting AUTH_I message from Bob.
        assertNull(c.clientAlice.receiveMessage());
        assertEquals(ENCRYPTED, c.clientAlice.session.getSessionStatus());

        for (int i = 0; i < 5; i++) {
            // Bob sending a message (alternating, to enable ratchet)
            final String messageBob = randomMessage(1000000);
            c.clientBob.sendMessage(messageBob);
            assertMessage("Iteration: " + i + ", message Bob: " + messageBob, messageBob, c.clientAlice.receiveMessage());
            // Alice sending a message (alternating, to enable ratchet)
            final String messageAlice = randomMessage(1000000);
            c.clientAlice.sendMessage(messageAlice);
            assertMessage("Iteration: " + i + ", message Alice: " + messageAlice, messageAlice, c.clientBob.receiveMessage());
        }
    }

    private static void assertMessage(final String message, final String expected, final String actual) {
        if (expected.length() == 0) {
            assertNull(message, actual);
        } else {
            assertEquals(message, expected, actual);
        }
    }

    private static String randomMessage(final int maxLength) {
        return randomMessage(0, maxLength);
    }

    private static String randomMessage(final int minLength, final int maxLength) {
        final byte[] arbitraryContent = new byte[minLength + RANDOM.nextInt(maxLength - minLength)];
        RANDOM.nextBytes(arbitraryContent);
        return toBase64String(arbitraryContent);
    }

    /**
     * Dummy conversation implementation, mimicking a conversation between two parties.
     */
    private static final class Conversation {

        private final SessionID sessionIDAlice;
        private final SessionID sessionIDBob;

        private final Client clientAlice;
        private final Client clientBob;

        private final BlockingSubmitter<String> submitterBob;
        private final BlockingSubmitter<String> submitterAlice;

        /**
         * Constructor with defaults: Unlimited-length messages.
         */
        private Conversation(final int channelCapacity) {
            final LinkedBlockingQueue<String> directChannelAlice = new LinkedBlockingQueue<>(channelCapacity);
            submitterAlice = new BlockingSubmitter<>();
            submitterAlice.addQueue(directChannelAlice);
            final LinkedBlockingQueue<String> directChannelBob = new LinkedBlockingQueue<>(channelCapacity);
            submitterBob = new BlockingSubmitter<>();
            submitterBob.addQueue(directChannelBob);
            this.sessionIDBob = new SessionID("bob@InMemoryNetwork4", "alice@InMemoryNetwork4",
                    "InMemoryNetwork4");
            this.sessionIDAlice = new SessionID("alice@InMemoryNetwork4", "bob@InMemoryNetwork4",
                    "InMemoryNetwork4");
            this.clientBob = new Client("Bob", sessionIDBob, new OtrPolicy(OTRL_POLICY_MANUAL), RANDOM,
                    submitterAlice, directChannelBob);
            this.clientAlice = new Client("Alice", sessionIDAlice, new OtrPolicy(OTRL_POLICY_MANUAL),
                    RANDOM, submitterBob, directChannelAlice);
        }

        /**
         * Constructor with configurable maximum message size and channel capacity (maximum number of messages
         * simultaneously stored).
         *
         * @param maxMessageSize  Maximum size of message allowed.
         * @param channelCapacity Maximum number of messages allowed to be in transit simultaneously.
         */
        private Conversation(final int channelCapacity, final int maxMessageSize) {
            final Predicate<String> condition = new MaxMessageSize(maxMessageSize);
            final ConditionalBlockingQueue<String> directChannelAlice = new ConditionalBlockingQueue<>(condition,
                    new LinkedBlockingQueue<String>(channelCapacity));
            submitterAlice = new BlockingSubmitter<>();
            submitterAlice.addQueue(directChannelAlice);
            final ConditionalBlockingQueue<String> directChannelBob = new ConditionalBlockingQueue<>(condition,
                    new LinkedBlockingQueue<String>(channelCapacity));
            submitterBob = new BlockingSubmitter<>();
            submitterBob.addQueue(directChannelBob);
            this.sessionIDBob = new SessionID("bob@InMemoryNetwork4", "alice@InMemoryNetwork4",
                    "InMemoryNetwork4");
            this.sessionIDAlice = new SessionID("alice@InMemoryNetwork4", "bob@InMemoryNetwork4",
                    "InMemoryNetwork4");
            this.clientBob = new Client("Bob", sessionIDBob, new OtrPolicy(OTRL_POLICY_MANUAL), RANDOM,
                    submitterAlice, directChannelBob);
            this.clientBob.setMessageSize(maxMessageSize);
            this.clientAlice = new Client("Alice", sessionIDAlice, new OtrPolicy(OTRL_POLICY_MANUAL),
                    RANDOM, submitterBob, directChannelAlice);
            this.clientAlice.setMessageSize(maxMessageSize);
        }
    }

    /**
     * Predicate to verify maximum message size.
     */
    private static final class MaxMessageSize implements Predicate<String> {
        private final int maximum;

        private MaxMessageSize(final int maximum) {
            this.maximum = maximum;
        }

        @Override
        public boolean test(@Nonnull final String s) {
            return s.length() <= maximum;
        }
    }

    /**
     * Dummy client implementation for use with OTRv4 protocol tests.
     */
    private static final class Client implements OtrEngineHost {

        private final Logger logger;

        private final HashSet<String> verified = new HashSet<>();

        private final InstanceTag instanceTag = InstanceTag.random(RANDOM);

        private final DSAKeyPair dsaKeyPair;

        private final EdDSAKeyPair ed448KeyPair;

        private final Point forgingPublicKey;

        private final BlockingSubmitter<String> sendChannel;

        private final BlockingQueue<String> receiptChannel;

        private final ClientProfile profile;

        private final Session session;

        private OtrPolicy policy;

        private int messageSize = MAX_VALUE;

        private Client(@Nonnull final String id, @Nonnull final SessionID sessionID, @Nonnull final OtrPolicy policy,
                @Nonnull final SecureRandom random, @Nonnull final BlockingSubmitter<String> sendChannel,
                @Nonnull final BlockingQueue<String> receiptChannel) {
            this.logger = Logger.getLogger(Client.class.getName() + ":" + id);
            this.ed448KeyPair = EdDSAKeyPair.generate(random);
            this.dsaKeyPair = generateDSAKeyPair();
            this.forgingPublicKey = EdDSAKeyPair.generate(RANDOM).getPublicKey();
            this.receiptChannel = requireNonNull(receiptChannel);
            this.sendChannel = requireNonNull(sendChannel);
            this.policy = requireNonNull(policy);
            final Calendar expirationCalendar = Calendar.getInstance();
            expirationCalendar.add(Calendar.DAY_OF_YEAR, 7);
            this.profile = new ClientProfile(this.instanceTag, this.ed448KeyPair.getPublicKey(), this.forgingPublicKey,
                    Collections.singleton(Session.Version.FOUR), null);
            this.session = createSession(sessionID, this);
        }

        void setMessageSize(final int messageSize) {
            this.messageSize = messageSize;
        }

        String receiveMessage() throws OtrException {
            final String msg = this.receiptChannel.remove();
            return this.session.transformReceiving(msg);
        }

        String[] receiveAllMessages(@SuppressWarnings("SameParameterValue") final boolean skipNulls) throws OtrException {
            final ArrayList<String> messages = new ArrayList<>();
            this.receiptChannel.drainTo(messages);
            final ArrayList<String> results = new ArrayList<>();
            for (final String msg : messages) {
                final String result = this.session.transformReceiving(msg);
                if (result == null && skipNulls) {
                    continue;
                }
                results.add(result);
            }
            return results.toArray(new String[0]);
        }

        void sendMessage(@Nonnull final String msg) throws OtrException {
            this.sendChannel.addAll(asList(this.session.transformSending(msg)));
        }

        void setPolicy(final OtrPolicy policy) {
            this.policy = requireNonNull(policy);
        }

        @Override
        public void injectMessage(@Nonnull final SessionID sessionID, @Nonnull final String msg) {
            this.sendChannel.add(msg);
        }

        @Override
        public void unreadableMessageReceived(@Nonnull final SessionID sessionID) {
            logger.finest("Unreadable message received. (Session: " + sessionID + ")");
        }

        @Override
        public void unencryptedMessageReceived(@Nonnull final SessionID sessionID, @Nonnull final String msg) {
            logger.finest("Message received unencrypted: " + msg + " (Session: " + sessionID + ")");
        }

        @Override
        public void showError(@Nonnull final SessionID sessionID, @Nonnull final String error) {
            logger.finest("OTR received an error: " + error + " (Session: " + sessionID + ")");
        }

        @Override
        public void finishedSessionMessage(@Nonnull final SessionID sessionID, @Nonnull final String msgText) {
            logger.finest("Encrypted session finished. (Session: " + sessionID + ")");
        }

        @Override
        public void requireEncryptedMessage(@Nonnull final SessionID sessionID, @Nonnull final String msgText) {
            logger.finest("Encrypted message is required. (Session: " + sessionID + "). Sent in plain text: " + msgText);
        }

        @Override
        public OtrPolicy getSessionPolicy(@Nonnull final SessionID sessionID) {
            return this.policy;
        }

        @Override
        public int getMaxFragmentSize(@Nonnull final SessionID sessionID) {
            return this.messageSize;
        }

        @Nonnull
        @Override
        public DSAKeyPair getLocalKeyPair(@Nonnull final SessionID sessionID) {
            return this.dsaKeyPair;
        }

        @Nonnull
        @Override
        public EdDSAKeyPair getLongTermKeyPair(@Nonnull final SessionID sessionID) {
            return this.ed448KeyPair;
        }

        @Nonnull
        @Override
        public ClientProfile getClientProfile(@Nonnull final SessionID sessionID) {
            return this.profile;
        }

        @Override
        public void askForSecret(@Nonnull final SessionID sessionID, @Nonnull final InstanceTag receiverTag, @Nullable final String question) {
            logger.finest("A request for the secret was received. (Question: " + question + ") [NOT IMPLEMENTED, LOGGING ONLY]");
        }

        @Nonnull
        @Override
        public byte[] getLocalFingerprintRaw(@Nonnull final SessionID sessionID) {
            return OtrCryptoEngine.getFingerprintRaw(this.dsaKeyPair.getPublic());
        }

        @Override
        public void smpError(@Nonnull final SessionID sessionID, final int tlvType, final boolean cheated) {
            logger.finest("SMP process resulted in error. (TLV type: " + tlvType + ", cheated: " + cheated + ", session: " + sessionID + ")");
        }

        @Override
        public void smpAborted(@Nonnull final SessionID sessionID) {
            logger.finest("SMP process is aborted. (Session: " + sessionID + ")");
        }

        @Override
        public void verify(@Nonnull final SessionID sessionID, @Nonnull final String fingerprint) {
            logger.finest("Verifying fingerprint " + fingerprint + " (Session: " + sessionID + ")");
            this.verified.add(fingerprint);
        }

        @Override
        public void unverify(@Nonnull final SessionID sessionID, @Nonnull final String fingerprint) {
            logger.finest("Invalidating fingerprint " + fingerprint + " (Session: " + sessionID + ")");
            this.verified.remove(fingerprint);
        }

        @Override
        public String getReplyForUnreadableMessage(@Nonnull final SessionID sessionID, @Nonnull final String identifier) {
            return "The message is unreadable. (Session: " + sessionID + ")";
        }

        @Override
        public String getFallbackMessage(@Nonnull final SessionID sessionID) {
            return null;
        }

        @Override
        public void messageFromAnotherInstanceReceived(@Nonnull final SessionID sessionID) {
            logger.finest("Message from another instance received. (Session: " + sessionID + ")");
        }

        @Override
        public void multipleInstancesDetected(@Nonnull final SessionID sessionID) {
            logger.finest("Multiple instances detected. (Session: " + sessionID + ")");
        }

        @Override
        public void extraSymmetricKeyDiscovered(@Nonnull final SessionID sessionID, @Nonnull final String message, @Nonnull final byte[] extraSymmetricKey, @Nonnull final byte[] tlvData) {
            logger.finest("Extra symmetric key TLV discovered in encoded message. (Session: " + sessionID + ")");
        }
    }
}
